# TODO: Test services.acme-dns.server.api.tls once
# https://github.com/joohoi/acme-dns/issues/214 is fixed.

let
  ipOf = node: node.config.networking.primaryIPAddress;

  common = { lib, nodes, ... }: {
    networking.nameservers = lib.mkForce [ (ipOf nodes.coredns) ];
  };
in

import ./make-test-python.nix {
  name = "acme-dns";

  nodes = {
    acme.imports = [ common ./common/acme/server ];

    acmedns = { nodes, pkgs, ... }: {
      imports = [ common ];

      networking.firewall = {
        allowedTCPPorts = [ 53 8053 ];
        allowedUDPPorts = [ 53 ];
      };

      services.acme-dns.server = {
        enable = true;
        api.ip = "0.0.0.0";
        general = {
          domain = "acme-dns.test";
          nsadmin = "hostmaster.acme-dns.test";
          records = [
            "acme-dns.test. A ${ipOf nodes.acmedns}"
            "acme-dns.test. NS acme-dns.test."
          ];
        };
      };
    };

    coredns = { nodes, pkgs, ... }: {
      imports = [ common ];

      networking.firewall = {
        allowedTCPPorts = [ 53 ];
        allowedUDPPorts = [ 53 ];
      };

      environment.etc."coredns/zones/db.example.test" = {
        text = ''
          $ORIGIN example.test.
          $TTL 3600
          @ SOA coredns.test. hostmaster.example.test. (
            1 ; serial
            86400 7200 600000 1
          )
          webserver A ${ipOf nodes.webserver}
        '';
        mode = "0644";
      };

      services.coredns = {
        enable = true;
        config = ''
          acme.test {
            template IN A {
              answer "{{ .Name }} 60 A ${ipOf nodes.acme}"
            }
          }

          acme-dns.test {
             forward . ${ipOf nodes.acmedns}
          }

          example.test {
            auto {
              directory /etc/coredns/zones
              reload 1s
            }
          }
        '';
      };
    };

    webserver = { config, pkgs, ... }: {
      imports = [ common ./common/acme/client ];

      security.acme.server = "https://acme.test/dir";

      security.acme.certs."example.test" = {
        domain = "*.example.test";
        user = "nginx";
        group = "nginx";
      };

      services.acme-dns.client = {
        enable = true;
        domains."example.test".server = "http://acme-dns.test:8053";
      };

      services.nginx.enable = true;

      nesting.clone = [
        {
          networking.firewall.allowedTCPPorts = [ 443 ];

          services.nginx.virtualHosts."webserver.example.test" = {
            onlySSL = true;
            useACMEHost = "example.test";
            locations."/".root = pkgs.runCommand "root" {} ''
              mkdir $out
              echo "hello world" > $out/index.html
            '';
          };
        }
      ];
    };

    webclient.imports = [ common ./common/acme/client ];
  };

  testScript = ''
    import json

    start_all()

    acme.wait_for_unit("pebble.service")
    acmedns.wait_for_unit("acme-dns.service")
    coredns.wait_for_unit("coredns.service")


    def acme_dns_check_failed(_) -> bool:
        print(
            repr(
                webserver.succeed(
                    "cat /var/lib/acme/example.test/acme-dns-486c565ab4cf6c5fc3451728d64c10015dadf156fff99397d9a5399b53485818.json || true"
                )
            )
        )
        info = webserver.get_unit_info("acme-dns-example.test-check.service")
        return info["ActiveState"] == "active"


    # Get the required CNAME record from the service error message.
    # webserver.wait_for_unit("acme-dns-example.test-register.service")
    # print(webserver.succeed("journalctl --unit=acme-dns-example.test-register.service"))
    retry(acme_dns_check_failed)
    print(webserver.succeed("journalctl --unit=acme-dns-example.test-check.service"))
    # acme_dns_domain = webserver.succeed(
    # "journalctl --no-pager --reverse --lines=1 "
    # "--unit=acme-dns-example.test-check.service "
    # "--grep='^  _acme-challenge\\.example\\.test\\. CNAME '"
    # ).split("CNAME ")[1]

    # zone_file = "/etc/coredns/zones/db.example.test"
    # coredns.succeed(
    # f"echo '_acme-challenge 1 CNAME {acme_dns_domain}' >> {zone_file}",
    # f"sed -i 's/1 ; serial/2 ; serial/' {zone_file}",
    # )

    # webserver.start_job("acme-example.test.service")
    # webserver.wait_for_unit("acme-example.test.service")
    # webserver.succeed(
    # "/run/current-system/fine-tune/child-1/bin/switch-to-configuration test"
    # )

    # webclient.wait_for_unit("default.target")
    # webclient.succeed("curl https://acme.test:15000/roots/0 > /tmp/ca.crt")
    # webclient.succeed("curl https://acme.test:15000/intermediate-keys/0 >> /tmp/ca.crt")
    # webclient.succeed(
    # "curl --cacert /tmp/ca.crt https://webserver.example.test | grep -qF 'hello world'"
    # )
  '';
}
