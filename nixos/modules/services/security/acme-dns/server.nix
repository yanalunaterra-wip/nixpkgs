{ config, lib, pkgs, ... }:

with lib;

let cfg = config.services.acme-dns.server; in

{
  options.services.acme-dns.server = {
    enable = mkEnableOption "acme-dns server";

    package = mkOption {
      type = types.package;
      default = pkgs.acme-dns;
      description = ''
        acme-dns package to use.
      '';
    };

    general = mkOption {
      description = "General configuration.";
      default = {};
      type = types.submodule {
        options = {
          listen = mkOption {
            type = types.str;
            description = "Interface to listen on for DNS.";
            default = ":53";
          };

          protocol = mkOption {
            type = types.enum [
              "udp" "udp4" "udp6"
              "tcp" "tcp4" "tcp6"
              "both" "both4" "both6"
            ];
            description = ''
              DNS protocols to service (UDP/TCP/both, IPv4/IPv6/both).
            '';
            default = "both";
          };

          domain = mkOption {
            type = types.str;
            description = ''
              Domain name to serve DNS records for, without
              trailing <literal>"."</literal>.
            '';
            example = "acme-dns.example.com";
          };

          nsname = mkOption {
            type = types.nullOr types.str;
            description = ''
              The primary name server for <option>domain</option>,
              without trailing <literal>"."</literal>; used for the
              MNAME field of SOA responses.

              Defaults to <option>domain</option>, which is probably
              what you want.
            '';
            default = null;
            defaultText = "config.services.acme-dns.general.domain";
            example = "acme-dns.example.com";
          };

          nsadmin = mkOption {
            type = types.str;
            description = ''
              Admin email address for SOA responses in RNAME format,
              with <literal>"@"</literal> replaced by
              <literal>"."</literal> and no trailing <literal>"."</literal>.

              If your email address's local-part has a
              <literal>"."</literal> in it, escape it like so:
              <literal>firstname\.lastname.example.com</literal>
            '';
            example = "hostmaster.example.com";
          };

          records = mkOption {
            type = types.listOf types.str;
            description = ''
              Static DNS records to serve.

              Make sure to add the A/AAAA/CNAME/NS records for
              <option>domain</option> to the authoritative DNS server
              for your root domain too.
            '';
            example = [
              "acme-dns.example.com. A your.ip.v4.address"
              "acme-dns.example.com. AAAA your:ip:v6::address"
              "acme-dns.example.com. NS acme-dns.example.com."
              "acme-dns.example.com. CAA 0 issue \"letsencrypt.org\""
            ];
          };

          debug = mkOption {
            type = types.bool;
            description = "Enable debug messages (CORS, ...?).";
            default = false;
          };
        };
      };
    };

    database = mkOption {
      description = "Database backend.";
      default = {};
      type = types.submodule {
        options = {
          engine = mkOption {
            type = types.enum [ "sqlite3" "postgres" ];
            description = "Database engine.";
            default = "sqlite3";
          };

          connection = mkOption {
            type = types.str;
            description = "Database connection string.";
            default = "/var/lib/acme-dns/acme-dns.db";
            # TODO: allow specification via file for passwords?
            example = "postgres://acme-dns@localhost/acme-dns";
          };
        };
      };
    };

    api = mkOption {
      description = "HTTP API configuration.";
      default = {};
      type = types.submodule {
        options = {
          ip = mkOption {
            type = types.str;
            description = "Host to listen on.";
            default = "localhost";
          };

          port = mkOption {
            type = types.int;
            description = "Port to listen on.";
            default = 8053;
          };

          disable_registration = mkOption {
            type = types.bool;
            description = ''
              Disables the registration endpoint. Note that this will
              prevent new domains in the client configurations from
              being automatically registered, so ensure that
              <literal>acme-dns-*-check.service</literal> succeed before
              you enable this.
            '';
            default = false;
          };

          tls = mkOption {
            # `cert` is deliberately not supported, as it's a hazard for
            # bootstrapping when the certificate expires; see
            # https://github.com/joohoi/acme-dns/blob/v0.8/README.md#https-api.
            #
            # If you really want to use it, this can be overridden
            # with `extraConfig`.
            type = types.enum [ "none" "letsencrypt" "letsencryptstaging" ];
            description = ''
              TLS backend to use. You should set this to
              <option>letsencrypt</option> if exposing the API over
              the internet.
            '';
            default = "none";
          };

          acme_cache_dir = mkOption {
            type = types.path;
            description = ''
              Directory to store ACME data for the HTTP API TLS
              certificate in when <option>tls = "letsencrypt"</option>.
            '';
            default = "/var/lib/acme-dns/api-certs";
            internal = true;
          };

          corsorigins = mkOption {
            type = types.listOf types.str;
            description = "CORS allowed origins";
            default = [ "*" ];
          };

          use_header = mkOption {
            type = types.bool;
            description = ''
              Get client IP from HTTP header
              (see <option>header_name</option>).
            '';
            default = false;
          };

          header_name = mkOption {
            type = types.str;
            description = "HTTP header name for <option>use_header</option>.";
            default = "X-Forwarded-For";
          };
        };
      };
    };

    logconfig = mkOption {
      description = "Logging configuration.";
      default = {};
      type = types.submodule {
        options = {
          loglevel = mkOption {
            type = types.enum [ "debug" "info" "warning" "error" ];
            description = "Minimum logging level.";
            default = "debug";
          };

          logtype = mkOption {
            type = types.enum [ "stdout" ];
            default = "stdout";
            # not currently customizable upstream
            internal = true;
          };

          logformat = mkOption {
            type = types.enum [ "text" "json" ];
            description = "Logging format.";
            default = "text";
          };
        };
      };
    };

    extraConfig = mkOption {
      # TODO: use YAML type instead
      type = types.attrs;
      description = "Unchecked additional configuration.";
      default = {};
    };

    configText = mkOption {
      type = types.nullOr types.lines;
      description = ''
        Literal TOML configuration text. Overrides other configuration
        options if set.
      '';
      default = null;
    };
  };

  config = let
    configFile = if cfg.configText != null
      then pkgs.writeText "acme-dns.toml" cfg.configText
      else let
        baseConfig = with cfg; {
          general = general //
            optionalAttrs (general.nsname == null) { nsname = general.domain; };
          inherit database;
          # TODO: https://github.com/joohoi/acme-dns/issues/218
          api = api // { port = toString api.port; };
          inherit logconfig;
        };

        fullConfig = recursiveUpdate baseConfig cfg.extraConfig;
      in pkgs.runCommand "acme-dns.toml" {} ''
        ${pkgs.remarshal}/bin/json2toml -o $out \
          <<<${escapeShellArg (builtins.toJSON fullConfig)}
      '';
  in mkIf cfg.enable {
    assertions = [
      {
        assertion = !hasInfix "@" cfg.general.nsadmin;
        message = ''
          Option services.acme-dns.general.nsadmin should contain a
          valid DNS SOA RNAME-format email address with the "@" replaced
          with ".".
        '';
      }
    ];

    systemd.services.acme-dns = {
      description = "acme-dns server";

      # We use network-online.target to ensure that acme-dns can reach
      # Let's Encrypt to renew its own HTTPS API certificate on
      # startup. This might be unnecessary if acme-dns is robust
      # enough to properly retry, in which case this could be removed.
      #
      # Note that this should probably *not* be replaced with
      # network.target unless necessary; see
      # https://www.freedesktop.org/wiki/Software/systemd/NetworkTarget/.
      after = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        ExecStart = "${cfg.package}/bin/acme-dns -c ${configFile}";

        Restart = "always";
        RestartSec = "10s";
        StartLimitInterval = "1min";

        # Set up /var/lib/acme-dns with appropriate permissions.
        StateDirectory = "acme-dns";
        StateDirectoryMode = "0700";

        # Run in an isolated filesystem namespace.
        # TODO: narrow down /etc further?
        TemporaryFileSystem = "/:ro";
        BindReadOnlyPaths = [ "/nix" "/etc" ];

        # Run as a dynamically-assigned user.
        DynamicUser = true;

        # Needs CAP_NET_BIND_SERVICE for binding to privileged ports.
        CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" ];
        AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];

        # NoNewPrivileges is implied by DynamicUser.

        # ProtectSystem=strict is implied by DynamicUser.

        # ProtectHome is redundant with TemporaryFileSystem.

        # PrivateTmp is implied by DynamicUser.

        # No need for direct device access.
        PrivateDevices = true;

        # Protect{KernelTunables,KernelModules,ControlGroups} should
        # hopefully not matter as we don't run as root to begin with.

        # Restrict the process to a narrow set of address families.
        RestrictedAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" ];

        # Don't allow the use of unprivileged user namespaces even if
        # enabled in the kernel; they're unneeded and have been the
        # cause of security bugs in the past.
        RestrictNamespaces = true;

        # Unusual personalities/architectures can have obscure bugs, and
        # we have no need for them.
        LockPersonality = true;

        # No JIT, so no need for W+X memory.
        MemoryDenyWriteExecute = true;

        # No need for realtime calls.
        RestrictRealtime = true;

        # RestrictSUIDGUID is implied by DynamicUser.

        # PrivateMounts is redundant with TemporaryFileSystem.

        # Restrict the set of available system calls.
        # TODO: narrow down further
        SystemCallFilter = "@system-service";
        SystemCallErrorNumber = "EPERM";

        # See LockPersonality.
        SystemCallArchitectures = "native";
      };
    };
  };
}
