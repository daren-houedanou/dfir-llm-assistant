{
  description = "dfir-llm-assistant: LLM-assisted DFIR triage for nix-forensics artifacts";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});

      mkPackage = pkgs:
        let py = pkgs.python3Packages; in
        py.buildPythonApplication {
          pname = "dfir-llm-assistant";
          version = "0.1.0";
          pyproject = true;
          src = ./.;
          build-system = [ py.hatchling ];
          dependencies = with py; [ httpx pyyaml rich typer textual ];
          nativeCheckInputs = [ py.pytestCheckHook py.pytest-asyncio pkgs.jq ];
          # evtx_dump (raw .evtx parsing) and jq (query validation) are used at runtime.
          makeWrapperArgs = [ "--prefix" "PATH" ":" (pkgs.lib.makeBinPath [ pkgs.evtx pkgs.jq ]) ];
          meta = {
            description = "LLM-assisted triage, correlation and query generation for DFIR artifacts";
            license = pkgs.lib.licenses.asl20;
            mainProgram = "dfa";
          };
        };
    in
    {
      packages = forAllSystems (pkgs: { default = mkPackage pkgs; });

      apps = forAllSystems (pkgs: {
        default = { type = "app"; program = "${self.packages.${pkgs.system}.default}/bin/dfa"; };
      });

      # Analyst / developer shell: the assistant plus the tools whose output it consumes.
      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [
            (pkgs.python3.withPackages (ps: with ps; [ httpx pyyaml rich typer textual pytest pytest-asyncio ]))
            pkgs.ruff
            pkgs.evtx # evtx_dump, the same tool nix-forensics ships as evtxTools
            pkgs.jq
            pkgs.kubectl
            pkgs.kustomize
            pkgs.ollama
          ];
          shellHook = ''
            export PYTHONPATH=$PWD/src''${PYTHONPATH:+:$PYTHONPATH}
            alias dfa="python -m dfirassist"
            echo "dfir-llm-assistant dev shell: run 'dfa --help'"
          '';
        };
      });

      # Drop-in for nix-forensics or a NixOS config: nixpkgs.overlays = [ dfir-llm-assistant.overlays.default ];
      overlays.default = final: prev: { dfir-llm-assistant = mkPackage final; };
    };
}
