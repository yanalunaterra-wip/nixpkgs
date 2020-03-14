{ config, lib, pkgs, ... }:

with lib;

let

  cfg = config.boot.initrd.network.ssh;

in

{

  options.boot.initrd.network.ssh = {
    enable = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Start SSH service during initrd boot. It can be used to debug failing
        boot on a remote server, enter pasphrase for an encrypted partition etc.
        Service is killed when stage-1 boot is finished.

        The configuration from <literal>options.services.openssh</literal>
        is inherited.
      '';
    };

    port = mkOption {
      type = types.int;
      default = 22;
      description = ''
        Port on which SSH initrd service should listen.
      '';
    };

    shell = mkOption {
      type = types.str;
      default = "/bin/ash";
      description = ''
        Login shell of the remote user. Can be used to limit actions user can do.
      '';
    };

    hostKeys = mkOption {
      type = types.listOf types.attrs;
      default =
        [ { type = "rsa"; bits = 4096; }
          { type = "ed25519"; }
        ];
      example =
        [ { type = "rsa"; bits = 4096; path = "/etc/secrets/initrd/ssh_host_rsa_key"; }
          { type = "ed25519"; path = "/etc/secrets/initrd/ssh_host_ed25519_key"; }
        ];
      description = ''
        Specify SSH host keys to generate or import into the initrd.
        Has the same format as <literal>options.services.openssh.hostKeys</literal>,
        except that if you specify <literal>path</literal>, it must exist and
        will be imported, and if not specified, a new key will be generated on
        each boot.

        WARNING: Unless your bootloader supports initrd secrets,
        any keys imported with <literal>path</literal> will be
        stored insecurely in the global Nix store. Do NOT use your regular
        SSH host private keys in this case or you'll expose them to
        regular users!
      '';
    };

    authorizedKeys = mkOption {
      type = types.listOf types.str;
      default = config.users.users.root.openssh.authorizedKeys.keys;
      defaultText = "config.users.users.root.openssh.authorizedKeys.keys";
      description = ''
        Authorized keys for the root user on initrd.
      '';
    };
  };

  imports =
    map (opt: mkRemovedOptionModule ([ "boot" "initrd" "network" "ssh" ] ++ [ opt ]) ''
      The initrd SSH functionality now uses OpenSSH rather than Dropbear.

      If you want to keep your existing initrd SSH host keys, convert them with
        dropbearconvert dropbear openssh dropbear_host_$type_key ssh_host_$type_key
      and then set options.boot.initrd.network.ssh.hostKeys, e.g.:
        [ { type = "rsa"; path = "/etc/secrets/initrd/ssh_host_rsa_key"; } ]
    '') [ "hostRSAKey" "hostDSSKey" "hostECDSAKey" ];

  config = let
    initrdKeyPath = k:
      if k ? path && isString k.path
        then k.path
        else
          # Nix complains if you include a store hash in initrd path
          # names, so here's an awful hack. It also helps us ensure
          # uniqueness for keys without a path set.
          let hash = builtins.hashString "sha256"
            (builtins.unsafeDiscardStringContext (builtins.toJSON k));
          in "/etc/ssh/ssh_host_${k.type}_key_${hash}";

  in mkIf (config.boot.initrd.network.enable && cfg.enable) {
    assertions = [
      { assertion = cfg.authorizedKeys != [];
        message = "You should specify at least one authorized key for initrd SSH";
      }
    ];

    boot.initrd.extraUtilsCommands = let
      # openssh-smol = pkgs.pkgsStatic.openssh.override {
      #  linkOpenssl = false;
      #  withKerberos = false;
      # };
      openssh-smol = pkgs.openssh;
    in ''
      copy_bin_and_libs ${openssh-smol}/bin/ssh-keygen
      copy_bin_and_libs ${openssh-smol}/bin/sshd
      cp -pv ${pkgs.glibc.out}/lib/libnss_files.so.* $out/lib
    '';

    boot.initrd.extraUtilsCommandsTest = ''
      # sshd requires a host key to check config, so we pass in the test's
      # echo -n ${escapeShellArg config.services.openssh.extraConfig} |
      #  $out/bin/sshd -t -f /dev/stdin \
      #  -h ${../../../tests/initrd-network-ssh/ssh_host_ed25519_key}
    '';

    boot.initrd.network.postCommands = ''
      echo '${cfg.shell}' > /etc/shells
      echo 'root:x:0:0:root:/root:${cfg.shell}' > /etc/passwd
      echo 'sshd:x:1:1:sshd:/var/empty:/bin/nologin' >> /etc/passwd
      echo 'passwd: files' > /etc/nsswitch.conf

      mkdir -p /var/log /var/empty
      touch /var/log/lastlog

      mkdir -p /etc/ssh
      echo -n ${escapeShellArg config.services.openssh.extraConfig} > /etc/ssh/sshd_config

      mkdir -p /root/.ssh
      ${concatStrings (map (key: ''
        echo ${escapeShellArg key} >> /root/.ssh/authorized_keys
      '') cfg.authorizedKeys)}

      ${flip concatMapStrings cfg.hostKeys (k: ''
        if [ -f "${initrdKeyPath k}" ]; then
          # mv $(readLink "${initrdKeyPath k}") "${initrdKeyPath k}"
          chmod 0600 "${initrdKeyPath k}"
        else
          # TODO: Fix duplication with nixos/modules/services/networking/ssh/sshd.nix
          ssh-keygen \
            -t "${k.type}" \
            ${if k ? bits then "-b ${toString k.bits}" else ""} \
            ${if k ? rounds then "-a ${toString k.rounds}" else ""} \
            ${if k ? comment then "-C '${k.comment}'" else ""} \
            ${if k ? openSSHFormat && k.openSSHFormat then "-o" else ""} \
             -f "${initrdKeyPath k}" \
            -N ""
        fi
      '')}

      /bin/sshd -e -p ${toString cfg.port} \
        ${concatMapStrings (k: " -h '${initrdKeyPath k}'") cfg.hostKeys}
    '';

    boot.initrd.secrets = listToAttrs (flip concatMap cfg.hostKeys (k:
      if k ? path
        then [ (nameValuePair (initrdKeyPath k) k.path) ]
        else []));
  };

}
