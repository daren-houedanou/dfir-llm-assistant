{
  description = "dfir-llm-assistant : assistant LLM pour l'analyse forensique des artefacts nix-forensics";

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
          # evtx_dump (lecture des .evtx bruts) et jq (validation des requêtes) sont utilisés à l'exécution.
          makeWrapperArgs = [ "--prefix" "PATH" ":" (pkgs.lib.makeBinPath [ pkgs.evtx pkgs.jq ]) ];
          meta = {
            description = "Tri, corrélation et génération de requêtes assistés par LLM pour les artefacts DFIR";
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

      # Shell analyste et développeur : l'assistant et les outils dont il lit les sorties.
      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [
            (pkgs.python3.withPackages (ps: with ps; [ httpx pyyaml rich typer textual pytest pytest-asyncio ]))
            pkgs.ruff
            pkgs.evtx # evtx_dump, le même outil que l'evtxTools de nix-forensics
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

      # À ajouter à nix-forensics ou à une configuration NixOS : nixpkgs.overlays = [ dfir-llm-assistant.overlays.default ];
      overlays.default = final: prev: { dfir-llm-assistant = mkPackage final; };
    };
}
