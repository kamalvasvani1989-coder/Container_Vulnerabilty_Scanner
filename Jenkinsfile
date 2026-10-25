// Container image vulnerability scan — Jenkins pipeline (Sprint 2).
//
// Same tool, same policy, same exit-code contract as the GitHub Actions
// workflow (.github/workflows/scan.yml):
//   scanner.py exit 0 -> PASS        build succeeds
//   scanner.py exit 1 -> POLICY FAIL build fails: "Blocked by policy"
//   scanner.py exit 2 -> TOOL ERROR  build fails: "Tool error, investigate"
// A broken scanner can never look like a passing build.
//
// Scan parameters ("Build with Parameters"):
//   SCAN_IMAGE   empty = build and scan this repo's Dockerfile;
//                or any image name to test sample images, e.g. python:3.9-slim
//   POLICY_FILE  which policy to apply (default policy.yaml)
//
// Slack: uses a Jenkins "Secret text" credential with ID slack-webhook-url.
// The webhook URL never appears in this file or in the build log.

pipeline {
    agent any

    parameters {
        string(name: 'SCAN_IMAGE', defaultValue: '',
               description: 'Leave empty to build and scan this repo\'s Dockerfile, or enter an image to scan (e.g. python:3.9-slim).')
        string(name: 'POLICY_FILE', defaultValue: 'policy.yaml',
               description: 'Policy file with the severity thresholds.')
    }

    triggers {
        // Jenkins runs locally, so GitHub can't call it. Check for new
        // commits every ~5 minutes instead (H spreads the load).
        pollSCM('H/5 * * * *')
    }

    options {
        timestamps()
        timeout(time: 20, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '30'))
    }

    environment {
        // Unique tag per build, removed again in post/cleanup.
        LOCAL_IMAGE = "vuln-scanner-test:jenkins-${env.BUILD_NUMBER}"
        VENV_PY     = '.venv/bin/python'
    }

    stages {
        stage('Resolve parameters') {
            steps {
                script {
                    // Read parameters through params.* (always populated with
                    // defaults, even on a job's very first build) and fall back
                    // to the default if a field is left empty. Later steps use
                    // these env values, never the raw parameter variables.
                    env.POLICY_PATH  = params.POLICY_FILE?.trim() ?: 'policy.yaml'
                    env.TARGET_IMAGE = params.SCAN_IMAGE?.trim() ?: env.LOCAL_IMAGE
                    echo "Image to scan: ${env.TARGET_IMAGE}"
                    echo "Policy file:   ${env.POLICY_PATH}"
                }
            }
        }

        stage('Set up Python') {
            steps {
                sh '''
                    python3 -m venv .venv
                    .venv/bin/pip install --quiet --upgrade pip
                    .venv/bin/pip install --quiet -r requirements.txt
                '''
            }
        }

        stage('Build image') {
            when { expression { !params.SCAN_IMAGE?.trim() } }
            steps {
                // Retry (Sprint 5): a base-image pull can fail briefly.
                // A real Dockerfile error fails all 3 tries, as it should.
                // Trivy itself is retried inside scanner.py.
                retry(3) {
                    sh 'docker build -t "$LOCAL_IMAGE" sample-app'
                }
            }
        }

        stage('Scan') {
            steps {
                script {
                    // returnStatus: we read the exit code ourselves instead of
                    // letting Jenkins fail here, so the report and archive
                    // stages still run on a FAIL or ERROR.
                    env.SCAN_EXIT = sh(
                        script: '$VENV_PY src/scanner.py "$TARGET_IMAGE" --policy "$POLICY_PATH" --output-dir reports',
                        returnStatus: true
                    ).toString()
                    echo "scanner.py exit code: ${env.SCAN_EXIT}"
                }
            }
        }

        stage('Report') {
            steps {
                // A reporting problem fails the build visibly, but the gate
                // and archive steps still run.
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                    sh '$VENV_PY src/report.py --input-dir reports --pdf'
                }
            }
        }

        stage('Policy gate') {
            steps {
                script {
                    switch (env.SCAN_EXIT) {
                        case '0':
                            echo 'PASS: policy satisfied.'
                            break
                        case '1':
                            error('Blocked by policy: the image exceeds the severity thresholds. See reports/report.html.')
                            break
                        case '2':
                            error('Tool error, investigate: the scanner could not complete. This is NOT a policy result.')
                            break
                        default:
                            error("Unexpected scanner exit code ${env.SCAN_EXIT}; treating as a tool error.")
                    }
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
        }
        failure {
            script {
                try {
                    withCredentials([string(credentialsId: 'slack-webhook-url', variable: 'SLACK_WEBHOOK_URL')]) {
                        // notify.py reads branch/commit from GitHub-style
                        // variables, so map Jenkins' own values onto them.
                        sh '''
                            GITHUB_REF_NAME="${GIT_BRANCH#origin/}" GITHUB_SHA="$GIT_COMMIT" \
                              $VENV_PY src/notify.py --input-dir reports --policy "${POLICY_PATH:-policy.yaml}"
                        '''
                    }
                } catch (err) {
                    echo "Slack alert not sent: ${err}. Check the slack-webhook-url credential."
                }
            }
        }
        cleanup {
            sh 'docker rmi -f "$LOCAL_IMAGE" >/dev/null 2>&1 || true'
            deleteDir()
        }
    }
}
