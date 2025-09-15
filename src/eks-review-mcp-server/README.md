# AWS Labs eks-review MCP Server

Analyzes EKS cluster configurations and provides expert recommendations to help you follow EKS and AWS Operational best practices

## Instructions

This MCP server performs operational reviews of Amazon EKS clusters.

## TODO (REMOVE AFTER COMPLETING)

* [ ] Optionally add an ["RFC issue"](https://github.com/awslabs/mcp/issues) for the community to review
* [ ] Generate a `uv.lock` file with `uv sync` -> See [Getting Started](https://docs.astral.sh/uv/getting-started/)
* [ ] Remove the example tools in `./awslabs/eks_review_mcp_server/server.py`
* [ ] Add your own tool(s) following the [DESIGN_GUIDELINES.md](https://github.com/awslabs/mcp/blob/main/DESIGN_GUIDELINES.md)
* [ ] Keep test coverage at or above the `main` branch - NOTE: GitHub Actions run this command for CodeCov metrics `uv run --frozen pytest --cov --cov-branch --cov-report=term-missing`
* [ ] Document the MCP Server in this "README.md"
* [ ] Add a section for this eks-review MCP Server at the top level of this repository "../../README.md"
* [ ] Create the "../../docusaraus/docs/servers/eks-review-mcp-server.md" file with these contents:

    ```markdown
    ---
    title: eks-review MCP Server
    ---

    import ReadmeContent from "../../../src/eks-review-mcp-server/README.md";

    <div className="readme-content">
      <style>
        {`
        .readme-content h1:first-of-type {
          display: none;
        }
        `}
      </style>
      <ReadmeContent />
    </div>
    ```
  
* [ ] Reference within the "../../docusaraus/sidebars.ts" in the appropriate category.
* [ ] Add an entry to "../../docusaraus/statics/assets/server-cards.json" in the servers json. 



* [ ] Submit a PR and pass all the checks
