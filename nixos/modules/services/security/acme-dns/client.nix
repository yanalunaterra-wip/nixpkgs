{ config, lib, pkgs, ... }:

with lib;

let cfg = config.services.acme-dns.client; in

{
  options.services.acme-dns.client = {
    enable = mkEnableOption "acme-dns client integration";

    domains = mkOption {
      description = ''
        Domains to register with an acme-dns server.

        The <option>security.acme.certs.*.{dnsProvider,acmeDnsFile}</option>
        options are filled in automatically for each domain specified.
      '';
      default = {};
      type = types.attrsOf (types.submodule ({ name, ... }: {
        options = {
          server = mkOption {
            type = types.nullOr types.str;
            description = ''
              The base URL of the acme-dns server's HTTP API. Uses the
              <option>services.acme-dns.server</option> configuration
              by default.
            '';
            default = null;
            example = "https://acme-dns.example.com";
          };

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
      cert = config.security.acme.certs.${domain};
      # We embed the configuration hash in the credentials path to ensure
      # that domains are re-registered on configuration changes.
      acmeDnsFile = let domainCfgHash = builtins.hashString "sha256"
        (builtins.toJSON domainCfg);
      in "${cert.directory}/acme-dns-${domainCfgHash}.json";
    };

    domainMapper = f: domain: baseCfg: f (domainEnv domain baseCfg);
    mapDomains = f: mapAttrs (domainMapper f) cfg.domains;
    mapDomainsToList = f: mapAttrsToList (domainMapper f) cfg.domains;
    mapDomains' = f: listToAttrs (mapDomainsToList f);
  in mkIf cfg.enable {

    security.acme.certs = mapDomains ({ domain, domainCfg, acmeDnsFile, ... }: {
      dnsProvider = lib.mkDefault "acme-dns";
      credentialsFile = lib.mkDefault
        (pkgs.writeText "lego-${domain}-acme-dns.env" ''
          ACME_DNS_API_BASE=${domainCfg.server}
          ACME_DNS_STORAGE_PATH=${acmeDnsFile}
        '');
    });

    systemd.services = let
      makeService = name: service: env:
        nameValuePair "acme-dns-${env.domain}-${name}" (service env);

      register = { domain, domainCfg, cert, acmeDnsFile, ... }: {
        description = "Register acme-dns subdomain for ${domain}";
        after = [ "network-online.target" ];
        # TODO FIXME: is openssl needed here?
        path = [ pkgs.curl pkgs.openssl pkgs.jq ];
        serviceConfig = {
          User = cert.user;
          Group = cert.group;
          # Ensure that the certificate directory exists.
          StateDirectory = "acme/${domain}";
          StateDirectoryMode = "0700";
        };
        # Only run if acme-dns-*.json doesn't already exist.
        unitConfig.ConditionPathExists = "!${acmeDnsFile}";
        script = let
          request = { allowfrom = domainCfg.allowUpdateFromIPs; };
        in ''
          # TODO: Use goacmedns-register? https://github.com/cpu/goacmedns/tree/f8552ac0b6b570f5fbdc3bcd2fa8487eff07f20f#pre-registration
          # (would require packaging goacmedns separately just for that command)
          curl --silent --show-error \
            -X POST '${domainCfg.server}/register' \
            --header 'Content-Type: application/json' \
            --data ${escapeShellArg (builtins.toJSON request)} \
            | jq '{${builtins.toJSON domain}: .}' > '${acmeDnsFile}'
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
        script = ''
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
