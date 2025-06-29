env 'MONGO_USERNAME', 'superuser'
env 'MONGO_PASSWORD', secret('mongodb_password')
env 'MONGO_DB_CREDS', nil
runner 'ubuntu-docker', 'ubuntu-latest'


transform "dependencyCheck" do |item| 
    additional_args = item["arguments"].find { |arg| arg["key"] == "additionalArguments" }["value"]["value"]

    format = additional_args.match(/--format ['"]([^'"]+)['"]/i)&.captures&.first || "ALL"
    fail_on_cvss = additional_args.match(/--failOnCVSS (\d+)/i)&.captures&.first || "9"

    {

        "name" => "Depcheck",
        "uses" => "dependency-check/Dependency-Check_Action@main",
        "with" => {
            "project" => "test",
            "path" => ".",
            "out" => "reports",
            "format" => format,
             "args" => "--failOnCVSS #{fail_on_cvss}"
        }
    }
end


transform "dependencyCheckPublisher" do |item|
    next nil
end

transform "retry" do |item|
    max_attempts = item["arguments"][0]["value"]

    [
        {
            "name" => "checkout",
            "uses" => "actions/checkout@v4"
        },
        {
        
            "name" => "install dependencies",
            "run" => "npm install -- no-audit",
            "shell" => "bash"
        },
        {
        "uses" => "nick-fields/retry@v3",
        "with" => {
        "timeout_minutes" => 60,
        "max_attempts" => max_attempts,
        "retry_on" => "error",
        "command" => "npm test"
            }
        },

        {
            "name" => "Publish Test Results",
            "uses" => "actions/upload-artifact@v3",
            "with" => {
            "name" => "test-results",
            "path" => "test-results.xml"
                }
        }

    ]
end


transform "catchError" do |item|
coverage_cmd = item.dig("children", 0, "arguments", 0, "value", "value") || "npm run coverage"

    [
        {

            "name" => "Install dependencies",
            "run" => "npm install --no-audit",
            "shell" => "bash"
        },

        {
            "name" => "Check Code Coverage",
            "continue-on-error" => true,
            "run" => coverage_cmd,
            "shell" => "bash"
        }

    ]
end






transform "sh" do |item|
  script = item.dig("arguments",0,"value","value").to_s
  
  if script.include?("docker build") && script.include?("siddharth67/solar-system")
    coverted_script = script
        .gsub('rattantiwana','${{ vars.DOCKERHUB_USERNAME }}')
        .gsub('solar-system','${{ vars.IMAGE_NAME }}')
        .gsub('$GIT_COMMIT','${{ github.sha }}')
    
    {

        "name" => "Docker Build",
        "run" => coverted_script,
        "shell" => "bash"
    }

    elsif script.match?(/^trivy image (?:siddharth67\/solar-system:\$GIT_COMMIT|\${{ .*?}}\/\${{ .*?}}:\${{ .*?}})/i)

        image_ref = script.match(/trivy image (\S+)/i)[1]
        severity = script.match(/--severity (\S+)/i)&.captures&.first || "CRITICAL"
        format = script.match(/--format (\S+)/i)&.captures&.first || "json"
        output_file = script.match(/-o (\S+)/i)&.captures&.first || "trivy-results.json"
        exit_code = (script.match(/--exit-code (\d+)/i)&.captures&.first || 1).to_i
        quiet = script.include?("--quiet")

        normalized_image_ref = if image_ref.include?("rattantiwana/solar-system")
            "${{ vars.DOCKERHUB_USERNAME}}/${{ vars.IMAGE_NAME}}:${{ github.sha}}"
        else
            image_ref
        end
        [
            {
                "name" => "Trivy Security Scan",
                "uses" => "aquasecurity/trivy-action@0.30.0",
                "with" => {
                    "image-ref" => normalized_image_ref,
                    "severity" => severity,
                    "format" => "template",
                    "template" => "@HOME/.local/bin/trivy-bin/contrib/html.tpl",
                    "output" => "trivy-results.html",
                    "exit-code" => exit_code,
                    "hide-progress" => quiet
                    }

            },
            {

                "name" => "Upload Scan Report",
                "if" => "${{ always() }}",
                "uses" => "actions/upload-artifact@v4",
                "with" => {
                    "name" => "Trivy Report",
                    "path" => "trivy-results.html"

                }
            }
        ]



    else
        next nil if item.dig("arguments",0,"value","value") == "npm test"
    end
end



transform "withDockerRegistry" do |item|
    push_command = item["children"].first["arguments"].find { |arg| arg["key"] == "script"}["value"]["value"]
    image_tag = push_command.split(' ').last

    [
        {
            "name" => "Login to Docker Hub",
            "uses" => "docker/login-action@v3",
            "with" => {
            "username" => "${{ vars.DOCKERHUB_USERNAME }}",
            "password" => "${{ secrets.DOCKERHUB_TOKEN }}"
                } 
        },
        {
            "name" => "Build and push",
            "uses" => "docker/build-push-action@v6",
            "with" => {
                "push" => true,
                "tags" => image_tag.gsub('siddharth67', '${{ vars.DOCKERHUB_USERNAME}}')
                                .gsub('solar-system', '${{ vars.IMAGE_NAME }}')
                                .gsub('$GIT_COMMIT', '${{ github.sha }}')
            }
        }
    ]
end











