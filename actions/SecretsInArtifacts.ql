/**
 * @id actions/secrets-in-artifacts
 * @name Secrets In Artifacts
 * @description Secrets can be written to files and uploaded as Artifacts
 * @kind problem
 * @problem.severity error
 */

import actions
import codeql.actions.TaintTracking
import codeql.actions.DataFlow
import codeql.actions.dataflow.FlowSources

from
  Env env, SecretsExpression secret, string envName, Run run, string command, string fileName,
  Uses uploadArtifact
where
  env.getEnvVarExpr(envName) = secret and
  run.getScript().getEnclosingStep().getEnv() = env and 
  run.getScript().getACommand() = command and
  (
    command.indexOf("$" + envName) >= 0 or
    command.indexOf("${" + envName + "}") >= 0
  ) and
  command.substring(command.indexOf(">>") + 2, command.length()).trim() = fileName and
  uploadArtifact.getCallee() = "actions/upload-artifact" and
  uploadArtifact.getArgument("path").trim() = fileName
select uploadArtifact,
  "$@ environment variable flows to file `" + fileName.trim() +
    "`, which is then uploaded as an artifact using $@` (path: `" +
    uploadArtifact.getArgument("path").trim() + "`). " + "This occurred in the command: `" + command
    + "`.", env, env.toString(), uploadArtifact, uploadArtifact.getCallee()
