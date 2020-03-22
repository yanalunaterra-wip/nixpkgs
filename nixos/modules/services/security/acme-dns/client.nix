{ config, lib, pkgs, ... }:

with lib;

let cfg = config.services.acme-dns.client; in

{
  options.services.acme-dns.client = {
    enable = mkEnableOption "acme-dns client integration";

    domains = mkOption {
      description = ''
        Domains to register with an acme-dns server.

        The <literal>security.acme.certs.*.{dnsProvider,acmeDnsFile}</literal>
        options are filled in automatically for each domain specified.
      '';
      default = {};
      type = types.attrsOf (types.submodule ({ name, ... }: {
        options = {
          certHost = mkOption {
            type = types.str;
            description = ''
              The <literal>security.acme.certs.*</literal> key to use with
              this domain registration.
            '';
            default = name;
          };

          server = mkOption {
            type = types.nullOr types.str;
            description = ''
              The base URL of the acme-dns server's HTTP API. Uses the
              <literal>services.acme-dns.server</literal> configuration
              by default.
            '';
            default = null;
            example = "https://acme-dns.example.com";
          };

          # TODO: re-register on change
          allowUpdateFromIPs = mkOption {
            type = types.listOf types.str;
            description = ''
              The IP ranges (in CIDR notation) allowed to update the
              DNS ACME challenge records for this domain name.

              Set to <literal>[]</literal> to allow all IPs.
            '';
            default = [];
          };
        };
      }));
      default = {};
      example = {
        "example.com" = {};
      };
    };
  };

  config = let
    domainEnv = domain: baseCfg: rec {
      inherit domain;
      domainCfg = baseCfg // optionalAttrs (baseCfg.server == null) {
        server = with config.services.acme-dns.server; let
          proto = if api.tls == "none" then "http" else "https";
        in "${proto}://${general.domain}:${toString api.port}";
      };
      cert = config.security.acme.certs.${domainCfg.certHost};
      acmeDnsFile = "${cert.directory}/acme-dns.json";
    };

    domainMapper = f: domain: baseCfg: f (domainEnv domain baseCfg);
    mapDomains = f: mapAttrs (domainMapper f) cfg.domains;
    mapDomainsToList = f: mapAttrsToList (domainMapper f) cfg.domains;
    mapDomains' = f: listToAttrs (mapDomainsToList f);
  in mkIf cfg.enable {
    # TODO: relax? (requirement is due to use of
    # systemd.services.*.serviceConfig.StateDirectory)
    assertions = mapDomainsToList ({ domainCfg, cert, ... }: {
      assertion = hasPrefix "/var/lib/" cert.directory;
      message = ''
        The acme-dns module requires that all certificates in
        services.acme-dns.domains must have a
        security.acme.certs.*.directory starting with /var/lib, but:

          security.acme.certs.${escapeNixString domainCfg.certHost}.directory = ${escapeNixString cert.directory};
      '';
    });

    security.acme.certs = mapDomains ({ domainCfg, acmeDnsFile, ... }: {
      dnsProvider = lib.mkDefault "acme-dns";
      enableCNAME = lib.mkDefault true;
      credentialsFile = lib.mkDefault
        (pkgs.writeText "lego-${domainCfg.certHost}-acme-dns.env" ''
          ACME_DNS_API_BASE=${domainCfg.server}
          ACME_DNS_STORAGE_PATH=${acmeDnsFile}
        '');
    });

    systemd.services = let
      makeService = name: service: env:
        nameValuePair "acme-dns-${env.domain}-${name}" (service env);

      register = { domain, domainCfg, cert, acmeDnsFile, ... }: {
        description = "Register acme-dns subdomain for ${domain}";
        # TODO FIXME: is openssl needed here?
        path = [ pkgs.curl pkgs.openssl ];
        serviceConfig = {
          User = cert.user;
          Group = cert.group;
          # Ensure that the certificate directory exists.
          StateDirectory = removePrefix "/var/lib/" cert.directory;
          StateDirectoryMode = "0700";
        };
        # Only run if acme-dns.json doesn't already exist.
        unitConfig.ConditionPathExists = "!${acmeDnsFile}";
        script = ''
          curl -X POST '${domainCfg.server}/register' \
            --header 'Content-Type: application/json' \
            --data ${escapeShellArg (builtins.toJSON {
              allowfrom = domainCfg.allowUpdateFromIPs;
            })} | jq '{
              # Translate from acme-dns response to goacmedns Account...
              #
              # See https://github.com/cpu/goacmedns/issues/7.
              #
              # This is gross, but less gross than lego unconditionally
              # failing without even bothering to check CNAME
              # after registration :(
              ${builtins.toJSON domainCfg.certHost}: {
                FullDomain: .fulldomain,
                SubDomain: .subdomain,
                Username: .username,
                Password: .password,
              }
            }' > '${acmeDnsFile}'
        '';
      };

      check = { domain, cert, acmeDnsFile, ... }: {
        description = "Check _acme-challenge DNS records for ${domain}";
        path = [ pkgs.dnsutils pkgs.jq ];
        serviceConfig = {
          User = cert.user;
          Group = cert.group;
        };
        requires = [ "acme-dns-${domain}-register.service" ];
        # We use `Requires` rather than `Wants` here to avoid falling
        # back to lego's built-in registration support, which doesn't
        # support setting the CIDR origin restrictions.
        requiredBy = [ "acme-${domain}.service" ];
        script = if !cert.dnsPropagationCheck then "" else ''
          src=_acme-challenge.${domain}.
          target=$(jq -r .fulldomain '${acmeDnsFile}')
          records=$(dig +short "$src")
          if ! grep -qF "$target" <<<"$records"; then
            echo "Required CNAME record for $src not found."
            echo "Existing records:"
            sed 's/^/  /' <<<"$records"
            echo "Please add the following DNS record:"
            echo "  $src CNAME $target."
            echo "and then run:"
            echo "  systemctl restart acme-${domain}"
            exit 1
          fi
        '';
      };
    in
      mapDomains' (makeService "register" register) //
      mapDomains' (makeService "check" check);
  };
}
