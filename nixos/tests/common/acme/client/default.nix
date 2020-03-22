{ lib, nodes, pkgs, ... }:

let
  acme-ca = nodes.acme.config.test-support.acme.caCert;
in

{
  networking.nameservers = [
    nodes.acme.config.networking.primaryIPAddress
  ];

  security.acme.acceptTerms = true;
  security.acme.email = "webmaster@example.com";

  security.pki.certificateFiles = [ acme-ca ];
}
