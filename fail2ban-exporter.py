from collections import defaultdict
from wsgiref.simple_server import make_server
import json
import subprocess
import yaml
from prometheus_client import make_wsgi_app
from prometheus_client.core import GaugeMetricFamily, REGISTRY


class Jail:
    def __init__(self, name):
        self.name = name
        self.ip_list = []


class F2bCollector:
    def __init__(self, conf):
        self.geo_provider = self._import_provider(conf)
        self.jails = []
        self.extra_labels = sorted(self.geo_provider.get_labels())

    def _import_provider(self, conf):
        if conf['geo']['enabled']:
            class_name = conf['geo']['provider']
            mod = __import__(f"geoip_provider.{class_name.lower()}", fromlist=[class_name])
        else:
            class_name = 'BaseProvider'
            mod = __import__('geoip_provider.base', fromlist=['BaseProvider'])

        GeoProvider = getattr(mod, class_name)
        return GeoProvider(conf)

    def get_jailed_ips(self):
        self.jails.clear()

        stdout = subprocess.run(['/usr/bin/fail2ban-client', 'banned'], check=True, capture_output=True).stdout.decode('utf-8')
        bans = json.loads(stdout.replace("'", "\""))

        for jaildict in bans:
            for jailname in jaildict:
                jail = Jail(jailname)
                for ip in jaildict[jail]:
                    jail.ip_list.append({'ip': ip})

                self.jails.append(jail)

    def assign_location(self):
        for jail in self.jails:
            for entry in jail.ip_list:
                entry.update(self.geo_provider.annotate(entry['ip']))

    def collect(self, conf):
        self.get_jailed_ips()
        self.assign_location()

        if conf['geo']['enable_grouping']:
            yield self.expose_grouped()
            yield self.expose_jail_summary()
        else:
            yield self.expose_single()

    def expose_single(self):
        metric_labels = ['jail','ip'] + self.extra_labels
        gauge = GaugeMetricFamily('fail2ban_banned_ip', 'IP banned by fail2ban', labels=metric_labels)

        for jail in self.jails:
            for entry in jail.ip_list:
                # Skip if GeoProvider.annotate() did not return matching count of labels
                if len(entry) < len(self.extra_labels) + 1:
                    continue
                values = [jail.name, entry['ip']] + [entry[x] for x in self.extra_labels]
                gauge.add_metric(values, 1)

        return gauge

    def expose_grouped(self):
        gauge = GaugeMetricFamily('fail2ban_location', 'Number of currently banned IPs from this location', labels=self.extra_labels)
        grouped = defaultdict(int)

        for jail in self.jails:
            for entry in jail.ip_list:
                if not entry:
                    continue
                location_key = tuple([entry[x] for x in self.extra_labels])
                grouped[location_key] += 1

        for labels, count in grouped.items():
            gauge.add_metric(list(labels), count)

        return gauge

    def expose_jail_summary(self):
        gauge = GaugeMetricFamily('fail2ban_jailed_ips', 'Number of currently banned IPs per jail', labels=['jail'])

        for jail in self.jails:
            gauge.add_metric([jail.name], len(jail.ip_list))

        return gauge


if __name__ == '__main__':
    with open('conf.yml', 'r', encoding='utf-8') as f:
        exp_conf = yaml.load(f, Loader=yaml.FullLoader)

    REGISTRY.register(F2bCollector(exp_conf))

    app = make_wsgi_app()
    httpd = make_server(exp_conf['server']['listen_address'], exp_conf['server']['port'], app)
    httpd.serve_forever()
