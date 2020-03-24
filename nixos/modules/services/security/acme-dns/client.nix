{ config, lib, pkgs, ... }:

with lib;

let cfg = config.services.acme-dns.client; in

{
  options.services.acme-dns.client = {
    enable = mkEnableOption "acme-dns client integration";

    domains = mkOption {
      description = ''
        Domains to register with an acme-dns server.

        The <option>security.acme.certs.*.{dnsProvider,credentialsFile}</option>
        options are filled in automatically for each domain specified.
      '';
      default = {};
      type = types.attrsOf (types.submodule ({ name, ... }: {
        options = {
          server = mkOption {
            type = types.nullOr types.str;
            description = ''
              The base URL of the acme-dns server's HTTP API.

              If <option>services.acme-dns.server</option> is enabled,
              defaults to <literal>$proto://$host:$port</literal>
              matching the server configuration. Note that if you set
              <option>services.acme-dns.server.api.tls</option> but
              <option>services.acme-dns.server.api.ip</option> is
              the default <literal>localhost</literal> or similar then
              you'll probably run into issues due to TLS certificate
              validation and will have to manually set this yourself.
              This is hard to handle automatically in all cases,
              unfortunately; if TLS is enabled then a query has to be
              via the domain name for certificate validation to pass,
              but we can't make requests via the domain name in the
              common case where acme-dns is running locally and only
              listening on loopback addresses.
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
    serverCfg = config.services.acme-dns.server;

    # See documentation of cfg.domains.*server option for caveats.
    localServer = let
      proto = if serverCfg.api.tls == "none" then "http" else "https";
      host = if elem serverCfg.api.ip [ "" "0.0.0.0" "[::]" ]
        then serverCfg.general.domain
        else serverCfg.api.ip;
    in "${proto}://${host}:${toString serverCfg.api.port}";

    domainEnv = domain: baseCfg: rec {
      inherit domain;
      domainCfg = baseCfg //
        optionalAttrs (baseCfg.server == null && serverCfg.enable)
          { server = localServer; };
      cert = config.security.acme.certs.${domain};
      # We embed the configuration hash in the credentials path to ensure
      # that domains are re-registered on configuration changes.
      acmeDnsFile = let
        domainCfgHash = builtins.hashString "sha256"
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

      register = { domain, domainCfg, cert, acmeDnsFile, ... }: let
        deps = [ "network-online.target" ] ++
          # We assume that if there's a local acme-dns server enabled
          # it's used by the acme-dns client and hence should be waited
          # on before attempting registration; we could check
          # domainCfg.server but it would potentially be brittle (e.g.
          # localhost vs. external domain name vs. internal IP).
          lib.optional serverCfg.enable "acme-dns.service";
      in {
        description = "Register acme-dns subdomain for ${domain}";
        wants = deps;
        after = deps;
        # TODO: is openssl needed here? (needs testing with HTTPS
        # acme-dns API)
        path = [ pkgs.curl pkgs.openssl pkgs.jq ];
        serviceConfig = {
          User = cert.user;
          Group = cert.group;
          # Ensure that the certificate directory exists.
          StateDirectory = "acme/${domain}";
          StateDirectoryMode = "0700";
        };
        unitConfig.ConditionPathExists = "!${acmeDnsFile}";
        script = let
          request = { allowfrom = domainCfg.allowUpdateFromIPs; };
        in ''
          # TODO: Use goacmedns-register? https://github.com/cpu/goacmedns/blob/v0.0.2/README.md#pre-registration
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
        # We need ${acmeDnsFile} to exist to check the CNAME record.
        requires = [ "acme-dns-${domain}-register.service" ];
        after = [ "acme-dns-${domain}-register.service" ];
        # We use requiredBy rather than wantedBy here to avoid falling
        # back to lego's built-in registration support, which doesn't
        # support setting the CIDR origin restrictions.
        requiredBy = [ "acme-${domain}.service" ];
        script = ''
          src=_acme-challenge.${domain}.
          target=$(jq -r '.${builtins.toJSON domain}.fulldomain' \
            '${acmeDnsFile}')
          records=$(dig +short "$src")
          if ! grep -qF "$target" <<<"$records"; then
            echo "Required CNAME record for $src not found."
            if [ -n "$records" ]; then
              echo "Existing records:"
              sed 's/^/  /' <<<"$records"
            fi
            echo "Please add the following DNS record:"
            echo "  $src CNAME $target."
            echo "and then run:"
            echo "  systemctl restart acme-${domain}.service"
            exit 1
          fi
        '';
      };
    in
      mapDomains' (makeService "register" register) //
      mapDomains' (makeService "check" check);
  };
}
