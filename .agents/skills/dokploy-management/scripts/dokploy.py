#!/usr/bin/env python3
# pyright: reportMissingImports=false
"""Dokploy REST API CLI wrapper for all available endpoints."""

import argparse
import json
import math
import os
import re
import sys

import httpx

ENDPOINTS = [
    {
        "tag": "admin",
        "m": "POST",
        "p": "/admin.setupMonitoring",
        "params": [
            {"n": "metricsConfig", "t": "object", "in": "body", "r": True},
        ],
    },
    {
        "tag": "ai",
        "m": "POST",
        "p": "/ai.analyzeLogs",
        "params": [
            {"n": "aiId", "t": "string", "in": "body", "r": True},
            {"n": "logs", "t": "string", "in": "body", "r": True},
            {"n": "context", "t": "string", "in": "body", "r": True, "e": ["build", "runtime"]},
        ],
    },
    {
        "tag": "ai",
        "m": "POST",
        "p": "/ai.create",
        "params": [
            {"n": "name", "t": "string", "in": "body", "r": True},
            {"n": "apiUrl", "t": "string", "in": "body", "r": True},
            {"n": "apiKey", "t": "string", "in": "body", "r": True},
            {"n": "model", "t": "string", "in": "body", "r": True},
            {"n": "isEnabled", "t": "boolean", "in": "body", "r": True},
        ],
    },
    {
        "tag": "ai",
        "m": "POST",
        "p": "/ai.delete",
        "params": [
            {"n": "aiId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "ai",
        "m": "POST",
        "p": "/ai.deploy",
        "params": [
            {"n": "environmentId", "t": "string", "in": "body", "r": True},
            {"n": "id", "t": "string", "in": "body", "r": True},
            {"n": "dockerCompose", "t": "string", "in": "body", "r": True},
            {"n": "envVariables", "t": "string", "in": "body", "r": True},
            {"n": "serverId", "t": "string", "in": "body"},
            {"n": "name", "t": "string", "in": "body", "r": True},
            {"n": "description", "t": "string", "in": "body", "r": True},
            {"n": "domains", "t": "array", "in": "body"},
            {"n": "configFiles", "t": "array", "in": "body"},
        ],
    },
    {
        "tag": "ai",
        "m": "GET",
        "p": "/ai.get",
        "params": [
            {"n": "aiId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "ai",
        "m": "GET",
        "p": "/ai.getAll",
        "params": [],
    },
    {
        "tag": "ai",
        "m": "GET",
        "p": "/ai.getEnabledProviders",
        "params": [],
    },
    {
        "tag": "ai",
        "m": "GET",
        "p": "/ai.getModels",
        "params": [
            {"n": "apiUrl", "t": "string", "in": "query", "r": True},
            {"n": "apiKey", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "ai",
        "m": "GET",
        "p": "/ai.one",
        "params": [
            {"n": "aiId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "ai",
        "m": "POST",
        "p": "/ai.suggest",
        "params": [
            {"n": "aiId", "t": "string", "in": "body", "r": True},
            {"n": "input", "t": "string", "in": "body", "r": True},
            {"n": "serverId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "ai",
        "m": "POST",
        "p": "/ai.testConnection",
        "params": [
            {"n": "apiUrl", "t": "string", "in": "body", "r": True},
            {"n": "apiKey", "t": "string", "in": "body", "r": True},
            {"n": "model", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "ai",
        "m": "POST",
        "p": "/ai.update",
        "params": [
            {"n": "aiId", "t": "string", "in": "body", "r": True},
            {"n": "name", "t": "string", "in": "body"},
            {"n": "apiUrl", "t": "string", "in": "body"},
            {"n": "apiKey", "t": "string", "in": "body"},
            {"n": "model", "t": "string", "in": "body"},
            {"n": "isEnabled", "t": "boolean", "in": "body"},
            {"n": "createdAt", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "application",
        "m": "POST",
        "p": "/application.cancelDeployment",
        "params": [
            {"n": "applicationId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "application",
        "m": "POST",
        "p": "/application.cleanQueues",
        "params": [
            {"n": "applicationId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "application",
        "m": "POST",
        "p": "/application.clearDeployments",
        "params": [
            {"n": "applicationId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "application",
        "m": "POST",
        "p": "/application.create",
        "params": [
            {"n": "name", "t": "string", "in": "body", "r": True},
            {"n": "appName", "t": "string", "in": "body"},
            {"n": "description", "t": "string", "in": "body"},
            {"n": "environmentId", "t": "string", "in": "body", "r": True},
            {"n": "serverId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "application",
        "m": "POST",
        "p": "/application.delete",
        "params": [
            {"n": "applicationId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "application",
        "m": "POST",
        "p": "/application.deploy",
        "params": [
            {"n": "applicationId", "t": "string", "in": "body", "r": True},
            {"n": "title", "t": "string", "in": "body"},
            {"n": "description", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "application",
        "m": "POST",
        "p": "/application.disconnectGitProvider",
        "params": [
            {"n": "applicationId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "application",
        "m": "POST",
        "p": "/application.dropDeployment",
        "params": [
            {"n": "applicationId", "t": "string", "in": "body", "r": True},
            {"n": "zip", "t": "file", "in": "body", "r": True},
            {"n": "dropBuildPath", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "application",
        "m": "POST",
        "p": "/application.killBuild",
        "params": [
            {"n": "applicationId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "application",
        "m": "POST",
        "p": "/application.markRunning",
        "params": [
            {"n": "applicationId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "application",
        "m": "POST",
        "p": "/application.move",
        "params": [
            {"n": "applicationId", "t": "string", "in": "body", "r": True},
            {"n": "targetEnvironmentId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "application",
        "m": "GET",
        "p": "/application.one",
        "params": [
            {"n": "applicationId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "application",
        "m": "GET",
        "p": "/application.readAppMonitoring",
        "params": [
            {"n": "appName", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "application",
        "m": "GET",
        "p": "/application.readLogs",
        "params": [
            {"n": "applicationId", "t": "string", "in": "query", "r": True},
            {"n": "tail", "t": "integer", "in": "query"},
            {"n": "since", "t": "string", "in": "query"},
            {"n": "search", "t": "string", "in": "query"},
        ],
    },
    {
        "tag": "application",
        "m": "GET",
        "p": "/application.readTraefikConfig",
        "params": [
            {"n": "applicationId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "application",
        "m": "POST",
        "p": "/application.redeploy",
        "params": [
            {"n": "applicationId", "t": "string", "in": "body", "r": True},
            {"n": "title", "t": "string", "in": "body"},
            {"n": "description", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "application",
        "m": "POST",
        "p": "/application.refreshToken",
        "params": [
            {"n": "applicationId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "application",
        "m": "POST",
        "p": "/application.reload",
        "params": [
            {"n": "appName", "t": "string", "in": "body", "r": True},
            {"n": "applicationId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "application",
        "m": "POST",
        "p": "/application.saveBitbucketProvider",
        "params": [
            {"n": "bitbucketBuildPath", "t": "string", "in": "body", "r": True},
            {"n": "bitbucketOwner", "t": "string", "in": "body", "r": True},
            {"n": "bitbucketRepository", "t": "string", "in": "body", "r": True},
            {"n": "bitbucketRepositorySlug", "t": "string", "in": "body", "r": True},
            {"n": "bitbucketId", "t": "string", "in": "body", "r": True},
            {"n": "applicationId", "t": "string", "in": "body", "r": True},
            {"n": "bitbucketBranch", "t": "string", "in": "body", "r": True},
            {"n": "enableSubmodules", "t": "boolean", "in": "body"},
            {"n": "watchPaths", "t": "array", "in": "body"},
        ],
    },
    {
        "tag": "application",
        "m": "POST",
        "p": "/application.saveBuildType",
        "params": [
            {"n": "applicationId", "t": "string", "in": "body", "r": True},
            {"n": "buildType", "t": "string", "in": "body", "r": True, "e": ["dockerfile", "heroku_buildpacks", "paketo_buildpacks", "nixpacks", "static", "railpack"]},
            {"n": "dockerfile", "t": "string", "in": "body", "r": True},
            {"n": "dockerContextPath", "t": "string", "in": "body", "r": True},
            {"n": "dockerBuildStage", "t": "string", "in": "body", "r": True},
            {"n": "herokuVersion", "t": "string", "in": "body", "r": True},
            {"n": "railpackVersion", "t": "string", "in": "body", "r": True},
            {"n": "publishDirectory", "t": "string", "in": "body"},
            {"n": "isStaticSpa", "t": "boolean", "in": "body"},
        ],
    },
    {
        "tag": "application",
        "m": "POST",
        "p": "/application.saveDockerProvider",
        "params": [
            {"n": "dockerImage", "t": "string", "in": "body", "r": True},
            {"n": "applicationId", "t": "string", "in": "body", "r": True},
            {"n": "username", "t": "string", "in": "body", "r": True},
            {"n": "password", "t": "string", "in": "body", "r": True},
            {"n": "registryUrl", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "application",
        "m": "POST",
        "p": "/application.saveEnvironment",
        "params": [
            {"n": "applicationId", "t": "string", "in": "body", "r": True},
            {"n": "env", "t": "string", "in": "body", "r": True},
            {"n": "buildArgs", "t": "string", "in": "body", "r": True},
            {"n": "buildSecrets", "t": "string", "in": "body", "r": True},
            {"n": "createEnvFile", "t": "boolean", "in": "body", "r": True},
        ],
    },
    {
        "tag": "application",
        "m": "POST",
        "p": "/application.saveGitProvider",
        "params": [
            {"n": "applicationId", "t": "string", "in": "body", "r": True},
            {"n": "customGitBuildPath", "t": "string", "in": "body", "r": True},
            {"n": "customGitUrl", "t": "string", "in": "body", "r": True},
            {"n": "watchPaths", "t": "array", "in": "body", "r": True},
            {"n": "enableSubmodules", "t": "boolean", "in": "body"},
            {"n": "customGitBranch", "t": "string", "in": "body", "r": True},
            {"n": "customGitSSHKeyId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "application",
        "m": "POST",
        "p": "/application.saveGiteaProvider",
        "params": [
            {"n": "applicationId", "t": "string", "in": "body", "r": True},
            {"n": "giteaBuildPath", "t": "string", "in": "body", "r": True},
            {"n": "giteaOwner", "t": "string", "in": "body", "r": True},
            {"n": "giteaRepository", "t": "string", "in": "body", "r": True},
            {"n": "giteaId", "t": "string", "in": "body", "r": True},
            {"n": "giteaBranch", "t": "string", "in": "body", "r": True},
            {"n": "enableSubmodules", "t": "boolean", "in": "body"},
            {"n": "watchPaths", "t": "array", "in": "body"},
        ],
    },
    {
        "tag": "application",
        "m": "POST",
        "p": "/application.saveGithubProvider",
        "params": [
            {"n": "applicationId", "t": "string", "in": "body", "r": True},
            {"n": "repository", "t": "string", "in": "body", "r": True},
            {"n": "owner", "t": "string", "in": "body", "r": True},
            {"n": "buildPath", "t": "string", "in": "body", "r": True},
            {"n": "githubId", "t": "string", "in": "body", "r": True},
            {"n": "branch", "t": "string", "in": "body", "r": True},
            {"n": "triggerType", "t": "string", "in": "body", "r": True, "e": ["push", "tag"]},
            {"n": "enableSubmodules", "t": "boolean", "in": "body"},
            {"n": "watchPaths", "t": "array", "in": "body"},
        ],
    },
    {
        "tag": "application",
        "m": "POST",
        "p": "/application.saveGitlabProvider",
        "params": [
            {"n": "applicationId", "t": "string", "in": "body", "r": True},
            {"n": "gitlabBuildPath", "t": "string", "in": "body", "r": True},
            {"n": "gitlabOwner", "t": "string", "in": "body", "r": True},
            {"n": "gitlabRepository", "t": "string", "in": "body", "r": True},
            {"n": "gitlabId", "t": "string", "in": "body", "r": True},
            {"n": "gitlabProjectId", "t": "number", "in": "body", "r": True},
            {"n": "gitlabPathNamespace", "t": "string", "in": "body", "r": True},
            {"n": "gitlabBranch", "t": "string", "in": "body", "r": True},
            {"n": "enableSubmodules", "t": "boolean", "in": "body"},
            {"n": "watchPaths", "t": "array", "in": "body"},
        ],
    },
    {
        "tag": "application",
        "m": "GET",
        "p": "/application.search",
        "params": [
            {"n": "q", "t": "string", "in": "query"},
            {"n": "name", "t": "string", "in": "query"},
            {"n": "appName", "t": "string", "in": "query"},
            {"n": "description", "t": "string", "in": "query"},
            {"n": "repository", "t": "string", "in": "query"},
            {"n": "owner", "t": "string", "in": "query"},
            {"n": "dockerImage", "t": "string", "in": "query"},
            {"n": "projectId", "t": "string", "in": "query"},
            {"n": "environmentId", "t": "string", "in": "query"},
            {"n": "limit", "t": "number", "in": "query"},
            {"n": "offset", "t": "number", "in": "query"},
        ],
    },
    {
        "tag": "application",
        "m": "POST",
        "p": "/application.start",
        "params": [
            {"n": "applicationId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "application",
        "m": "POST",
        "p": "/application.stop",
        "params": [
            {"n": "applicationId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "application",
        "m": "POST",
        "p": "/application.update",
        "params": [
            {"n": "applicationId", "t": "string", "in": "body", "r": True},
            {"n": "name", "t": "string", "in": "body"},
            {"n": "appName", "t": "string", "in": "body"},
            {"n": "description", "t": "string", "in": "body"},
            {"n": "env", "t": "string", "in": "body"},
            {"n": "previewEnv", "t": "string", "in": "body"},
            {"n": "watchPaths", "t": "array", "in": "body"},
            {"n": "previewBuildArgs", "t": "string", "in": "body"},
            {"n": "previewBuildSecrets", "t": "string", "in": "body"},
            {"n": "previewLabels", "t": "array", "in": "body"},
            {"n": "previewWildcard", "t": "string", "in": "body"},
            {"n": "previewPort", "t": "number", "in": "body"},
            {"n": "previewHttps", "t": "boolean", "in": "body"},
            {"n": "previewPath", "t": "string", "in": "body"},
            {"n": "previewCertificateType", "t": "string", "in": "body", "e": ["letsencrypt", "none", "custom"]},
            {"n": "previewCustomCertResolver", "t": "string", "in": "body"},
            {"n": "previewLimit", "t": "number", "in": "body"},
            {"n": "isPreviewDeploymentsActive", "t": "boolean", "in": "body"},
            {"n": "previewRequireCollaboratorPermissions", "t": "boolean", "in": "body"},
            {"n": "rollbackActive", "t": "boolean", "in": "body"},
            {"n": "buildArgs", "t": "string", "in": "body"},
            {"n": "buildSecrets", "t": "string", "in": "body"},
            {"n": "memoryReservation", "t": "string", "in": "body"},
            {"n": "memoryLimit", "t": "string", "in": "body"},
            {"n": "cpuReservation", "t": "string", "in": "body"},
            {"n": "cpuLimit", "t": "string", "in": "body"},
            {"n": "title", "t": "string", "in": "body"},
            {"n": "enabled", "t": "boolean", "in": "body"},
            {"n": "subtitle", "t": "string", "in": "body"},
            {"n": "command", "t": "string", "in": "body"},
            {"n": "args", "t": "array", "in": "body"},
            {"n": "icon", "t": "string", "in": "body"},
            {"n": "refreshToken", "t": "string", "in": "body"},
            {"n": "sourceType", "t": "string", "in": "body", "e": ["github", "docker", "git", "gitlab", "bitbucket", "gitea", "drop"]},
            {"n": "cleanCache", "t": "boolean", "in": "body"},
            {"n": "repository", "t": "string", "in": "body"},
            {"n": "owner", "t": "string", "in": "body"},
            {"n": "branch", "t": "string", "in": "body"},
            {"n": "buildPath", "t": "string", "in": "body"},
            {"n": "triggerType", "t": "string", "in": "body", "e": ["push", "tag"]},
            {"n": "autoDeploy", "t": "boolean", "in": "body"},
            {"n": "gitlabProjectId", "t": "number", "in": "body"},
            {"n": "gitlabRepository", "t": "string", "in": "body"},
            {"n": "gitlabOwner", "t": "string", "in": "body"},
            {"n": "gitlabBranch", "t": "string", "in": "body"},
            {"n": "gitlabBuildPath", "t": "string", "in": "body"},
            {"n": "gitlabPathNamespace", "t": "string", "in": "body"},
            {"n": "giteaRepository", "t": "string", "in": "body"},
            {"n": "giteaOwner", "t": "string", "in": "body"},
            {"n": "giteaBranch", "t": "string", "in": "body"},
            {"n": "giteaBuildPath", "t": "string", "in": "body"},
            {"n": "bitbucketRepository", "t": "string", "in": "body"},
            {"n": "bitbucketRepositorySlug", "t": "string", "in": "body"},
            {"n": "bitbucketOwner", "t": "string", "in": "body"},
            {"n": "bitbucketBranch", "t": "string", "in": "body"},
            {"n": "bitbucketBuildPath", "t": "string", "in": "body"},
            {"n": "username", "t": "string", "in": "body"},
            {"n": "password", "t": "string", "in": "body"},
            {"n": "dockerImage", "t": "string", "in": "body"},
            {"n": "registryUrl", "t": "string", "in": "body"},
            {"n": "customGitUrl", "t": "string", "in": "body"},
            {"n": "customGitBranch", "t": "string", "in": "body"},
            {"n": "customGitBuildPath", "t": "string", "in": "body"},
            {"n": "customGitSSHKeyId", "t": "string", "in": "body"},
            {"n": "enableSubmodules", "t": "boolean", "in": "body"},
            {"n": "dockerfile", "t": "string", "in": "body"},
            {"n": "dockerContextPath", "t": "string", "in": "body"},
            {"n": "dockerBuildStage", "t": "string", "in": "body"},
            {"n": "dropBuildPath", "t": "string", "in": "body"},
            {"n": "healthCheckSwarm", "t": "object", "in": "body"},
            {"n": "restartPolicySwarm", "t": "object", "in": "body"},
            {"n": "placementSwarm", "t": "object", "in": "body"},
            {"n": "updateConfigSwarm", "t": "object", "in": "body"},
            {"n": "rollbackConfigSwarm", "t": "object", "in": "body"},
            {"n": "modeSwarm", "t": "object", "in": "body"},
            {"n": "labelsSwarm", "t": "object", "in": "body"},
            {"n": "networkSwarm", "t": "array", "in": "body"},
            {"n": "stopGracePeriodSwarm", "t": "number", "in": "body"},
            {"n": "endpointSpecSwarm", "t": "object", "in": "body"},
            {"n": "ulimitsSwarm", "t": "array", "in": "body"},
            {"n": "replicas", "t": "number", "in": "body"},
            {"n": "applicationStatus", "t": "string", "in": "body", "e": ["idle", "running", "done", "error"]},
            {"n": "buildType", "t": "string", "in": "body", "e": ["dockerfile", "heroku_buildpacks", "paketo_buildpacks", "nixpacks", "static", "railpack"]},
            {"n": "railpackVersion", "t": "string", "in": "body"},
            {"n": "herokuVersion", "t": "string", "in": "body"},
            {"n": "publishDirectory", "t": "string", "in": "body"},
            {"n": "isStaticSpa", "t": "boolean", "in": "body"},
            {"n": "createEnvFile", "t": "boolean", "in": "body"},
            {"n": "createdAt", "t": "string", "in": "body"},
            {"n": "registryId", "t": "string", "in": "body"},
            {"n": "rollbackRegistryId", "t": "string", "in": "body"},
            {"n": "environmentId", "t": "string", "in": "body"},
            {"n": "githubId", "t": "string", "in": "body"},
            {"n": "gitlabId", "t": "string", "in": "body"},
            {"n": "giteaId", "t": "string", "in": "body"},
            {"n": "bitbucketId", "t": "string", "in": "body"},
            {"n": "buildServerId", "t": "string", "in": "body"},
            {"n": "buildRegistryId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "application",
        "m": "POST",
        "p": "/application.updateTraefikConfig",
        "params": [
            {"n": "applicationId", "t": "string", "in": "body", "r": True},
            {"n": "traefikConfig", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "auditLog",
        "m": "GET",
        "p": "/auditLog.all",
        "params": [
            {"n": "userId", "t": "string", "in": "query"},
            {"n": "userEmail", "t": "string", "in": "query"},
            {"n": "resourceName", "t": "string", "in": "query"},
            {"n": "action", "t": "string", "in": "query", "e": ["create", "update", "delete", "deploy", "cancel", "redeploy", "login", "logout"]},
            {"n": "resourceType", "t": "string", "in": "query", "e": ["project", "service", "environment", "deployment", "user", "customRole", "domain", "certificate", "registry", "server", "sshKey", "gitProvider", "notification", "settings", "session"]},
            {"n": "from", "t": "string", "in": "query"},
            {"n": "to", "t": "string", "in": "query"},
            {"n": "limit", "t": "number", "in": "query"},
            {"n": "offset", "t": "number", "in": "query"},
        ],
    },
    {
        "tag": "backup",
        "m": "POST",
        "p": "/backup.create",
        "params": [
            {"n": "schedule", "t": "string", "in": "body", "r": True},
            {"n": "enabled", "t": "boolean", "in": "body"},
            {"n": "prefix", "t": "string", "in": "body", "r": True},
            {"n": "destinationId", "t": "string", "in": "body", "r": True},
            {"n": "keepLatestCount", "t": "number", "in": "body"},
            {"n": "database", "t": "string", "in": "body", "r": True},
            {"n": "mariadbId", "t": "string", "in": "body"},
            {"n": "mysqlId", "t": "string", "in": "body"},
            {"n": "postgresId", "t": "string", "in": "body"},
            {"n": "mongoId", "t": "string", "in": "body"},
            {"n": "libsqlId", "t": "string", "in": "body"},
            {"n": "databaseType", "t": "string", "in": "body", "r": True, "e": ["postgres", "mariadb", "mysql", "mongo", "web-server", "libsql"]},
            {"n": "userId", "t": "string", "in": "body"},
            {"n": "backupType", "t": "string", "in": "body", "e": ["database", "compose"]},
            {"n": "composeId", "t": "string", "in": "body"},
            {"n": "serviceName", "t": "string", "in": "body"},
            {"n": "metadata", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "backup",
        "m": "GET",
        "p": "/backup.listBackupFiles",
        "params": [
            {"n": "destinationId", "t": "string", "in": "query", "r": True},
            {"n": "search", "t": "string", "in": "query", "r": True},
            {"n": "serverId", "t": "string", "in": "query"},
        ],
    },
    {
        "tag": "backup",
        "m": "POST",
        "p": "/backup.manualBackupCompose",
        "params": [
            {"n": "backupId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "backup",
        "m": "POST",
        "p": "/backup.manualBackupLibsql",
        "params": [
            {"n": "backupId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "backup",
        "m": "POST",
        "p": "/backup.manualBackupMariadb",
        "params": [
            {"n": "backupId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "backup",
        "m": "POST",
        "p": "/backup.manualBackupMongo",
        "params": [
            {"n": "backupId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "backup",
        "m": "POST",
        "p": "/backup.manualBackupMySql",
        "params": [
            {"n": "backupId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "backup",
        "m": "POST",
        "p": "/backup.manualBackupPostgres",
        "params": [
            {"n": "backupId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "backup",
        "m": "POST",
        "p": "/backup.manualBackupWebServer",
        "params": [
            {"n": "backupId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "backup",
        "m": "GET",
        "p": "/backup.one",
        "params": [
            {"n": "backupId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "backup",
        "m": "POST",
        "p": "/backup.remove",
        "params": [
            {"n": "backupId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "backup",
        "m": "POST",
        "p": "/backup.update",
        "params": [
            {"n": "schedule", "t": "string", "in": "body", "r": True},
            {"n": "enabled", "t": "boolean", "in": "body", "r": True},
            {"n": "prefix", "t": "string", "in": "body", "r": True},
            {"n": "backupId", "t": "string", "in": "body", "r": True},
            {"n": "destinationId", "t": "string", "in": "body", "r": True},
            {"n": "database", "t": "string", "in": "body", "r": True},
            {"n": "keepLatestCount", "t": "number", "in": "body", "r": True},
            {"n": "serviceName", "t": "string", "in": "body", "r": True},
            {"n": "metadata", "t": "string", "in": "body", "r": True},
            {"n": "databaseType", "t": "string", "in": "body", "r": True, "e": ["postgres", "mariadb", "mysql", "mongo", "web-server", "libsql"]},
        ],
    },
    {
        "tag": "bitbucket",
        "m": "GET",
        "p": "/bitbucket.bitbucketProviders",
        "params": [],
    },
    {
        "tag": "bitbucket",
        "m": "POST",
        "p": "/bitbucket.create",
        "params": [
            {"n": "bitbucketId", "t": "string", "in": "body"},
            {"n": "bitbucketUsername", "t": "string", "in": "body"},
            {"n": "bitbucketEmail", "t": "string", "in": "body"},
            {"n": "appPassword", "t": "string", "in": "body"},
            {"n": "apiToken", "t": "string", "in": "body"},
            {"n": "bitbucketWorkspaceName", "t": "string", "in": "body"},
            {"n": "gitProviderId", "t": "string", "in": "body"},
            {"n": "authId", "t": "string", "in": "body", "r": True},
            {"n": "name", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "bitbucket",
        "m": "GET",
        "p": "/bitbucket.getBitbucketBranches",
        "params": [
            {"n": "owner", "t": "string", "in": "query", "r": True},
            {"n": "repo", "t": "string", "in": "query", "r": True},
            {"n": "bitbucketId", "t": "string", "in": "query"},
        ],
    },
    {
        "tag": "bitbucket",
        "m": "GET",
        "p": "/bitbucket.getBitbucketRepositories",
        "params": [
            {"n": "bitbucketId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "bitbucket",
        "m": "GET",
        "p": "/bitbucket.one",
        "params": [
            {"n": "bitbucketId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "bitbucket",
        "m": "POST",
        "p": "/bitbucket.testConnection",
        "params": [
            {"n": "bitbucketId", "t": "string", "in": "body", "r": True},
            {"n": "bitbucketUsername", "t": "string", "in": "body"},
            {"n": "bitbucketEmail", "t": "string", "in": "body"},
            {"n": "workspaceName", "t": "string", "in": "body"},
            {"n": "apiToken", "t": "string", "in": "body"},
            {"n": "appPassword", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "bitbucket",
        "m": "POST",
        "p": "/bitbucket.update",
        "params": [
            {"n": "bitbucketId", "t": "string", "in": "body", "r": True},
            {"n": "bitbucketUsername", "t": "string", "in": "body"},
            {"n": "bitbucketEmail", "t": "string", "in": "body"},
            {"n": "appPassword", "t": "string", "in": "body"},
            {"n": "apiToken", "t": "string", "in": "body"},
            {"n": "bitbucketWorkspaceName", "t": "string", "in": "body"},
            {"n": "gitProviderId", "t": "string", "in": "body", "r": True},
            {"n": "name", "t": "string", "in": "body", "r": True},
            {"n": "organizationId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "certificates",
        "m": "GET",
        "p": "/certificates.all",
        "params": [],
    },
    {
        "tag": "certificates",
        "m": "POST",
        "p": "/certificates.create",
        "params": [
            {"n": "certificateId", "t": "string", "in": "body"},
            {"n": "name", "t": "string", "in": "body", "r": True},
            {"n": "certificateData", "t": "string", "in": "body", "r": True},
            {"n": "privateKey", "t": "string", "in": "body", "r": True},
            {"n": "certificatePath", "t": "string", "in": "body"},
            {"n": "autoRenew", "t": "boolean", "in": "body"},
            {"n": "organizationId", "t": "string", "in": "body", "r": True},
            {"n": "serverId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "certificates",
        "m": "GET",
        "p": "/certificates.one",
        "params": [
            {"n": "certificateId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "certificates",
        "m": "POST",
        "p": "/certificates.remove",
        "params": [
            {"n": "certificateId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "certificates",
        "m": "POST",
        "p": "/certificates.update",
        "params": [
            {"n": "certificateId", "t": "string", "in": "body", "r": True},
            {"n": "name", "t": "string", "in": "body"},
            {"n": "certificateData", "t": "string", "in": "body"},
            {"n": "privateKey", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "cluster",
        "m": "GET",
        "p": "/cluster.addManager",
        "params": [
            {"n": "serverId", "t": "string", "in": "query"},
        ],
    },
    {
        "tag": "cluster",
        "m": "GET",
        "p": "/cluster.addWorker",
        "params": [
            {"n": "serverId", "t": "string", "in": "query"},
        ],
    },
    {
        "tag": "cluster",
        "m": "GET",
        "p": "/cluster.getNodes",
        "params": [
            {"n": "serverId", "t": "string", "in": "query"},
        ],
    },
    {
        "tag": "cluster",
        "m": "POST",
        "p": "/cluster.removeWorker",
        "params": [
            {"n": "nodeId", "t": "string", "in": "body", "r": True},
            {"n": "serverId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "compose",
        "m": "POST",
        "p": "/compose.cancelDeployment",
        "params": [
            {"n": "composeId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "compose",
        "m": "POST",
        "p": "/compose.cleanQueues",
        "params": [
            {"n": "composeId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "compose",
        "m": "POST",
        "p": "/compose.clearDeployments",
        "params": [
            {"n": "composeId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "compose",
        "m": "POST",
        "p": "/compose.create",
        "params": [
            {"n": "name", "t": "string", "in": "body", "r": True},
            {"n": "description", "t": "string", "in": "body"},
            {"n": "environmentId", "t": "string", "in": "body", "r": True},
            {"n": "composeType", "t": "string", "in": "body", "e": ["docker-compose", "stack"]},
            {"n": "appName", "t": "string", "in": "body"},
            {"n": "serverId", "t": "string", "in": "body"},
            {"n": "composeFile", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "compose",
        "m": "POST",
        "p": "/compose.delete",
        "params": [
            {"n": "composeId", "t": "string", "in": "body", "r": True},
            {"n": "deleteVolumes", "t": "boolean", "in": "body", "r": True},
        ],
    },
    {
        "tag": "compose",
        "m": "POST",
        "p": "/compose.deploy",
        "params": [
            {"n": "composeId", "t": "string", "in": "body", "r": True},
            {"n": "title", "t": "string", "in": "body"},
            {"n": "description", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "compose",
        "m": "POST",
        "p": "/compose.deployTemplate",
        "params": [
            {"n": "environmentId", "t": "string", "in": "body", "r": True},
            {"n": "serverId", "t": "string", "in": "body"},
            {"n": "id", "t": "string", "in": "body", "r": True},
            {"n": "baseUrl", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "compose",
        "m": "POST",
        "p": "/compose.disconnectGitProvider",
        "params": [
            {"n": "composeId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "compose",
        "m": "POST",
        "p": "/compose.fetchSourceType",
        "params": [
            {"n": "composeId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "compose",
        "m": "GET",
        "p": "/compose.getConvertedCompose",
        "params": [
            {"n": "composeId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "compose",
        "m": "GET",
        "p": "/compose.getDefaultCommand",
        "params": [
            {"n": "composeId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "compose",
        "m": "GET",
        "p": "/compose.getTags",
        "params": [
            {"n": "baseUrl", "t": "string", "in": "query"},
        ],
    },
    {
        "tag": "compose",
        "m": "POST",
        "p": "/compose.import",
        "params": [
            {"n": "base64", "t": "string", "in": "body", "r": True},
            {"n": "composeId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "compose",
        "m": "POST",
        "p": "/compose.isolatedDeployment",
        "params": [
            {"n": "composeId", "t": "string", "in": "body", "r": True},
            {"n": "suffix", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "compose",
        "m": "POST",
        "p": "/compose.killBuild",
        "params": [
            {"n": "composeId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "compose",
        "m": "GET",
        "p": "/compose.loadMountsByService",
        "params": [
            {"n": "composeId", "t": "string", "in": "query", "r": True},
            {"n": "serviceName", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "compose",
        "m": "GET",
        "p": "/compose.loadServices",
        "params": [
            {"n": "composeId", "t": "string", "in": "query", "r": True},
            {"n": "type", "t": "string", "in": "query", "e": ["fetch", "cache"]},
        ],
    },
    {
        "tag": "compose",
        "m": "POST",
        "p": "/compose.move",
        "params": [
            {"n": "composeId", "t": "string", "in": "body", "r": True},
            {"n": "targetEnvironmentId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "compose",
        "m": "GET",
        "p": "/compose.one",
        "params": [
            {"n": "composeId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "compose",
        "m": "POST",
        "p": "/compose.previewTemplate",
        "params": [
            {"n": "base64", "t": "string", "in": "body", "r": True},
            {"n": "appName", "t": "string", "in": "body", "r": True},
            {"n": "serverId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "compose",
        "m": "POST",
        "p": "/compose.processTemplate",
        "params": [
            {"n": "base64", "t": "string", "in": "body", "r": True},
            {"n": "composeId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "compose",
        "m": "POST",
        "p": "/compose.randomizeCompose",
        "params": [
            {"n": "composeId", "t": "string", "in": "body", "r": True},
            {"n": "suffix", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "compose",
        "m": "GET",
        "p": "/compose.readLogs",
        "params": [
            {"n": "composeId", "t": "string", "in": "query", "r": True},
            {"n": "containerId", "t": "string", "in": "query", "r": True},
            {"n": "tail", "t": "integer", "in": "query"},
            {"n": "since", "t": "string", "in": "query"},
            {"n": "search", "t": "string", "in": "query"},
        ],
    },
    {
        "tag": "compose",
        "m": "POST",
        "p": "/compose.redeploy",
        "params": [
            {"n": "composeId", "t": "string", "in": "body", "r": True},
            {"n": "title", "t": "string", "in": "body"},
            {"n": "description", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "compose",
        "m": "POST",
        "p": "/compose.refreshToken",
        "params": [
            {"n": "composeId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "compose",
        "m": "POST",
        "p": "/compose.saveEnvironment",
        "params": [
            {"n": "composeId", "t": "string", "in": "body", "r": True},
            {"n": "env", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "compose",
        "m": "GET",
        "p": "/compose.search",
        "params": [
            {"n": "q", "t": "string", "in": "query"},
            {"n": "name", "t": "string", "in": "query"},
            {"n": "appName", "t": "string", "in": "query"},
            {"n": "description", "t": "string", "in": "query"},
            {"n": "projectId", "t": "string", "in": "query"},
            {"n": "environmentId", "t": "string", "in": "query"},
            {"n": "limit", "t": "number", "in": "query"},
            {"n": "offset", "t": "number", "in": "query"},
        ],
    },
    {
        "tag": "compose",
        "m": "POST",
        "p": "/compose.start",
        "params": [
            {"n": "composeId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "compose",
        "m": "POST",
        "p": "/compose.stop",
        "params": [
            {"n": "composeId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "compose",
        "m": "GET",
        "p": "/compose.templates",
        "params": [
            {"n": "baseUrl", "t": "string", "in": "query"},
        ],
    },
    {
        "tag": "compose",
        "m": "POST",
        "p": "/compose.update",
        "params": [
            {"n": "composeId", "t": "string", "in": "body", "r": True},
            {"n": "name", "t": "string", "in": "body"},
            {"n": "appName", "t": "string", "in": "body"},
            {"n": "description", "t": "string", "in": "body"},
            {"n": "env", "t": "string", "in": "body"},
            {"n": "composeFile", "t": "string", "in": "body"},
            {"n": "refreshToken", "t": "string", "in": "body"},
            {"n": "sourceType", "t": "string", "in": "body", "e": ["git", "github", "gitlab", "bitbucket", "gitea", "raw"]},
            {"n": "composeType", "t": "string", "in": "body", "e": ["docker-compose", "stack"]},
            {"n": "repository", "t": "string", "in": "body"},
            {"n": "owner", "t": "string", "in": "body"},
            {"n": "branch", "t": "string", "in": "body"},
            {"n": "autoDeploy", "t": "boolean", "in": "body"},
            {"n": "gitlabProjectId", "t": "number", "in": "body"},
            {"n": "gitlabRepository", "t": "string", "in": "body"},
            {"n": "gitlabOwner", "t": "string", "in": "body"},
            {"n": "gitlabBranch", "t": "string", "in": "body"},
            {"n": "gitlabPathNamespace", "t": "string", "in": "body"},
            {"n": "bitbucketRepository", "t": "string", "in": "body"},
            {"n": "bitbucketRepositorySlug", "t": "string", "in": "body"},
            {"n": "bitbucketOwner", "t": "string", "in": "body"},
            {"n": "bitbucketBranch", "t": "string", "in": "body"},
            {"n": "giteaRepository", "t": "string", "in": "body"},
            {"n": "giteaOwner", "t": "string", "in": "body"},
            {"n": "giteaBranch", "t": "string", "in": "body"},
            {"n": "customGitUrl", "t": "string", "in": "body"},
            {"n": "customGitBranch", "t": "string", "in": "body"},
            {"n": "customGitSSHKeyId", "t": "string", "in": "body"},
            {"n": "command", "t": "string", "in": "body"},
            {"n": "enableSubmodules", "t": "boolean", "in": "body"},
            {"n": "composePath", "t": "string", "in": "body"},
            {"n": "suffix", "t": "string", "in": "body"},
            {"n": "randomize", "t": "boolean", "in": "body"},
            {"n": "isolatedDeployment", "t": "boolean", "in": "body"},
            {"n": "isolatedDeploymentsVolume", "t": "boolean", "in": "body"},
            {"n": "triggerType", "t": "string", "in": "body", "e": ["push", "tag"]},
            {"n": "composeStatus", "t": "string", "in": "body", "e": ["idle", "running", "done", "error"]},
            {"n": "environmentId", "t": "string", "in": "body"},
            {"n": "createdAt", "t": "string", "in": "body"},
            {"n": "watchPaths", "t": "array", "in": "body"},
            {"n": "githubId", "t": "string", "in": "body"},
            {"n": "gitlabId", "t": "string", "in": "body"},
            {"n": "bitbucketId", "t": "string", "in": "body"},
            {"n": "giteaId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "customRole",
        "m": "GET",
        "p": "/customRole.all",
        "params": [],
    },
    {
        "tag": "customRole",
        "m": "POST",
        "p": "/customRole.create",
        "params": [
            {"n": "roleName", "t": "string", "in": "body", "r": True},
            {"n": "permissions", "t": "object", "in": "body", "r": True},
        ],
    },
    {
        "tag": "customRole",
        "m": "GET",
        "p": "/customRole.getStatements",
        "params": [],
    },
    {
        "tag": "customRole",
        "m": "GET",
        "p": "/customRole.membersByRole",
        "params": [
            {"n": "roleName", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "customRole",
        "m": "POST",
        "p": "/customRole.remove",
        "params": [
            {"n": "roleName", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "customRole",
        "m": "POST",
        "p": "/customRole.update",
        "params": [
            {"n": "roleName", "t": "string", "in": "body", "r": True},
            {"n": "newRoleName", "t": "string", "in": "body"},
            {"n": "permissions", "t": "object", "in": "body", "r": True},
        ],
    },
    {
        "tag": "deployment",
        "m": "GET",
        "p": "/deployment.all",
        "params": [
            {"n": "applicationId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "deployment",
        "m": "GET",
        "p": "/deployment.allByCompose",
        "params": [
            {"n": "composeId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "deployment",
        "m": "GET",
        "p": "/deployment.allByServer",
        "params": [
            {"n": "serverId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "deployment",
        "m": "GET",
        "p": "/deployment.allByType",
        "params": [
            {"n": "id", "t": "string", "in": "query", "r": True},
            {"n": "type", "t": "string", "in": "query", "r": True, "e": ["application", "compose", "server", "schedule", "previewDeployment", "backup", "volumeBackup"]},
        ],
    },
    {
        "tag": "deployment",
        "m": "GET",
        "p": "/deployment.allCentralized",
        "params": [],
    },
    {
        "tag": "deployment",
        "m": "POST",
        "p": "/deployment.killProcess",
        "params": [
            {"n": "deploymentId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "deployment",
        "m": "GET",
        "p": "/deployment.queueList",
        "params": [],
    },
    {
        "tag": "deployment",
        "m": "GET",
        "p": "/deployment.readLogs",
        "params": [
            {"n": "deploymentId", "t": "string", "in": "query", "r": True},
            {"n": "tail", "t": "integer", "in": "query"},
        ],
    },
    {
        "tag": "deployment",
        "m": "POST",
        "p": "/deployment.removeDeployment",
        "params": [
            {"n": "deploymentId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "destination",
        "m": "GET",
        "p": "/destination.all",
        "params": [],
    },
    {
        "tag": "destination",
        "m": "POST",
        "p": "/destination.create",
        "params": [
            {"n": "name", "t": "string", "in": "body", "r": True},
            {"n": "provider", "t": "string", "in": "body", "r": True},
            {"n": "accessKey", "t": "string", "in": "body", "r": True},
            {"n": "bucket", "t": "string", "in": "body", "r": True},
            {"n": "region", "t": "string", "in": "body", "r": True},
            {"n": "endpoint", "t": "string", "in": "body", "r": True},
            {"n": "secretAccessKey", "t": "string", "in": "body", "r": True},
            {"n": "additionalFlags", "t": "array", "in": "body", "r": True},
            {"n": "serverId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "destination",
        "m": "GET",
        "p": "/destination.one",
        "params": [
            {"n": "destinationId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "destination",
        "m": "POST",
        "p": "/destination.remove",
        "params": [
            {"n": "destinationId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "destination",
        "m": "POST",
        "p": "/destination.testConnection",
        "params": [
            {"n": "name", "t": "string", "in": "body", "r": True},
            {"n": "provider", "t": "string", "in": "body", "r": True},
            {"n": "accessKey", "t": "string", "in": "body", "r": True},
            {"n": "bucket", "t": "string", "in": "body", "r": True},
            {"n": "region", "t": "string", "in": "body", "r": True},
            {"n": "endpoint", "t": "string", "in": "body", "r": True},
            {"n": "secretAccessKey", "t": "string", "in": "body", "r": True},
            {"n": "additionalFlags", "t": "array", "in": "body", "r": True},
            {"n": "serverId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "destination",
        "m": "POST",
        "p": "/destination.update",
        "params": [
            {"n": "name", "t": "string", "in": "body", "r": True},
            {"n": "accessKey", "t": "string", "in": "body", "r": True},
            {"n": "bucket", "t": "string", "in": "body", "r": True},
            {"n": "region", "t": "string", "in": "body", "r": True},
            {"n": "endpoint", "t": "string", "in": "body", "r": True},
            {"n": "secretAccessKey", "t": "string", "in": "body", "r": True},
            {"n": "destinationId", "t": "string", "in": "body", "r": True},
            {"n": "provider", "t": "string", "in": "body", "r": True},
            {"n": "additionalFlags", "t": "array", "in": "body", "r": True},
            {"n": "serverId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "docker",
        "m": "GET",
        "p": "/docker.getConfig",
        "params": [
            {"n": "containerId", "t": "string", "in": "query", "r": True},
            {"n": "serverId", "t": "string", "in": "query"},
        ],
    },
    {
        "tag": "docker",
        "m": "GET",
        "p": "/docker.getContainers",
        "params": [
            {"n": "serverId", "t": "string", "in": "query"},
        ],
    },
    {
        "tag": "docker",
        "m": "GET",
        "p": "/docker.getContainersByAppLabel",
        "params": [
            {"n": "appName", "t": "string", "in": "query", "r": True},
            {"n": "serverId", "t": "string", "in": "query"},
            {"n": "type", "t": "string", "in": "query", "r": True, "e": ["standalone", "swarm"]},
        ],
    },
    {
        "tag": "docker",
        "m": "GET",
        "p": "/docker.getContainersByAppNameMatch",
        "params": [
            {"n": "appType", "t": "string", "in": "query", "e": ["stack", "docker-compose"]},
            {"n": "appName", "t": "string", "in": "query", "r": True},
            {"n": "serverId", "t": "string", "in": "query"},
        ],
    },
    {
        "tag": "docker",
        "m": "GET",
        "p": "/docker.getServiceContainersByAppName",
        "params": [
            {"n": "appName", "t": "string", "in": "query", "r": True},
            {"n": "serverId", "t": "string", "in": "query"},
        ],
    },
    {
        "tag": "docker",
        "m": "GET",
        "p": "/docker.getStackContainersByAppName",
        "params": [
            {"n": "appName", "t": "string", "in": "query", "r": True},
            {"n": "serverId", "t": "string", "in": "query"},
        ],
    },
    {
        "tag": "docker",
        "m": "POST",
        "p": "/docker.killContainer",
        "params": [
            {"n": "containerId", "t": "string", "in": "body", "r": True},
            {"n": "serverId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "docker",
        "m": "POST",
        "p": "/docker.removeContainer",
        "params": [
            {"n": "containerId", "t": "string", "in": "body", "r": True},
            {"n": "serverId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "docker",
        "m": "POST",
        "p": "/docker.restartContainer",
        "params": [
            {"n": "containerId", "t": "string", "in": "body", "r": True},
            {"n": "serverId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "docker",
        "m": "POST",
        "p": "/docker.startContainer",
        "params": [
            {"n": "containerId", "t": "string", "in": "body", "r": True},
            {"n": "serverId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "docker",
        "m": "POST",
        "p": "/docker.stopContainer",
        "params": [
            {"n": "containerId", "t": "string", "in": "body", "r": True},
            {"n": "serverId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "docker",
        "m": "POST",
        "p": "/docker.uploadFileToContainer",
        "params": [
            {"n": "containerId", "t": "string", "in": "body", "r": True},
            {"n": "file", "t": "file", "in": "body", "r": True},
            {"n": "destinationPath", "t": "string", "in": "body", "r": True},
            {"n": "serverId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "domain",
        "m": "GET",
        "p": "/domain.byApplicationId",
        "params": [
            {"n": "applicationId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "domain",
        "m": "GET",
        "p": "/domain.byComposeId",
        "params": [
            {"n": "composeId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "domain",
        "m": "GET",
        "p": "/domain.canGenerateTraefikMeDomains",
        "params": [
            {"n": "serverId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "domain",
        "m": "POST",
        "p": "/domain.create",
        "params": [
            {"n": "host", "t": "string", "in": "body", "r": True},
            {"n": "path", "t": "string", "in": "body"},
            {"n": "port", "t": "number", "in": "body"},
            {"n": "customEntrypoint", "t": "string", "in": "body"},
            {"n": "https", "t": "boolean", "in": "body"},
            {"n": "applicationId", "t": "string", "in": "body"},
            {"n": "certificateType", "t": "string", "in": "body", "e": ["letsencrypt", "none", "custom"]},
            {"n": "customCertResolver", "t": "string", "in": "body"},
            {"n": "composeId", "t": "string", "in": "body"},
            {"n": "serviceName", "t": "string", "in": "body"},
            {"n": "domainType", "t": "string", "in": "body", "e": ["compose", "application", "preview"]},
            {"n": "previewDeploymentId", "t": "string", "in": "body"},
            {"n": "internalPath", "t": "string", "in": "body"},
            {"n": "stripPath", "t": "boolean", "in": "body"},
            {"n": "middlewares", "t": "array", "in": "body"},
            {"n": "forwardAuthEnabled", "t": "boolean", "in": "body"},
        ],
    },
    {
        "tag": "domain",
        "m": "POST",
        "p": "/domain.delete",
        "params": [
            {"n": "domainId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "domain",
        "m": "POST",
        "p": "/domain.generateDomain",
        "params": [
            {"n": "appName", "t": "string", "in": "body", "r": True},
            {"n": "serverId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "domain",
        "m": "GET",
        "p": "/domain.one",
        "params": [
            {"n": "domainId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "domain",
        "m": "POST",
        "p": "/domain.update",
        "params": [
            {"n": "host", "t": "string", "in": "body", "r": True},
            {"n": "path", "t": "string", "in": "body"},
            {"n": "port", "t": "number", "in": "body"},
            {"n": "customEntrypoint", "t": "string", "in": "body"},
            {"n": "https", "t": "boolean", "in": "body"},
            {"n": "certificateType", "t": "string", "in": "body", "e": ["letsencrypt", "none", "custom"]},
            {"n": "customCertResolver", "t": "string", "in": "body"},
            {"n": "serviceName", "t": "string", "in": "body"},
            {"n": "domainType", "t": "string", "in": "body", "e": ["compose", "application", "preview"]},
            {"n": "internalPath", "t": "string", "in": "body"},
            {"n": "stripPath", "t": "boolean", "in": "body"},
            {"n": "middlewares", "t": "array", "in": "body"},
            {"n": "forwardAuthEnabled", "t": "boolean", "in": "body"},
            {"n": "domainId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "domain",
        "m": "POST",
        "p": "/domain.validateDomain",
        "params": [
            {"n": "domain", "t": "string", "in": "body", "r": True},
            {"n": "serverIp", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "forwardAuth",
        "m": "GET",
        "p": "/forwardAuth.getAuthDomain",
        "params": [
            {"n": "serverId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "forwardAuth",
        "m": "GET",
        "p": "/forwardAuth.listProviders",
        "params": [],
    },
    {
        "tag": "forwardAuth",
        "m": "GET",
        "p": "/forwardAuth.serverStatus",
        "params": [],
    },
    {
        "tag": "forwardAuth",
        "m": "GET",
        "p": "/forwardAuth.status",
        "params": [
            {"n": "domainId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "forwardAuth",
        "m": "POST",
        "p": "/forwardAuth.deployOnServer",
        "params": [
            {"n": "serverId", "t": "string", "in": "body", "r": True},
            {"n": "providerId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "forwardAuth",
        "m": "POST",
        "p": "/forwardAuth.disable",
        "params": [
            {"n": "domainId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "forwardAuth",
        "m": "POST",
        "p": "/forwardAuth.enable",
        "params": [
            {"n": "domainId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "forwardAuth",
        "m": "POST",
        "p": "/forwardAuth.removeAuthDomain",
        "params": [
            {"n": "serverId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "forwardAuth",
        "m": "POST",
        "p": "/forwardAuth.removeOnServer",
        "params": [
            {"n": "serverId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "forwardAuth",
        "m": "POST",
        "p": "/forwardAuth.setAuthDomain",
        "params": [
            {"n": "serverId", "t": "string", "in": "body", "r": True},
            {"n": "authDomain", "t": "string", "in": "body", "r": True},
            {"n": "https", "t": "boolean", "in": "body"},
            {"n": "certificateType", "t": "string", "in": "body", "e": ["none", "letsencrypt", "custom"]},
            {"n": "customCertResolver", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "environment",
        "m": "GET",
        "p": "/environment.byProjectId",
        "params": [
            {"n": "projectId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "environment",
        "m": "POST",
        "p": "/environment.create",
        "params": [
            {"n": "name", "t": "string", "in": "body", "r": True},
            {"n": "description", "t": "string", "in": "body"},
            {"n": "projectId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "environment",
        "m": "POST",
        "p": "/environment.duplicate",
        "params": [
            {"n": "environmentId", "t": "string", "in": "body", "r": True},
            {"n": "name", "t": "string", "in": "body", "r": True},
            {"n": "description", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "environment",
        "m": "GET",
        "p": "/environment.one",
        "params": [
            {"n": "environmentId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "environment",
        "m": "POST",
        "p": "/environment.remove",
        "params": [
            {"n": "environmentId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "environment",
        "m": "GET",
        "p": "/environment.search",
        "params": [
            {"n": "q", "t": "string", "in": "query"},
            {"n": "name", "t": "string", "in": "query"},
            {"n": "description", "t": "string", "in": "query"},
            {"n": "projectId", "t": "string", "in": "query"},
            {"n": "limit", "t": "number", "in": "query"},
            {"n": "offset", "t": "number", "in": "query"},
        ],
    },
    {
        "tag": "environment",
        "m": "POST",
        "p": "/environment.update",
        "params": [
            {"n": "environmentId", "t": "string", "in": "body", "r": True},
            {"n": "name", "t": "string", "in": "body"},
            {"n": "description", "t": "string", "in": "body"},
            {"n": "projectId", "t": "string", "in": "body"},
            {"n": "env", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "gitProvider",
        "m": "GET",
        "p": "/gitProvider.allForPermissions",
        "params": [],
    },
    {
        "tag": "gitProvider",
        "m": "GET",
        "p": "/gitProvider.getAll",
        "params": [],
    },
    {
        "tag": "gitProvider",
        "m": "POST",
        "p": "/gitProvider.remove",
        "params": [
            {"n": "gitProviderId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "gitProvider",
        "m": "POST",
        "p": "/gitProvider.toggleShare",
        "params": [
            {"n": "gitProviderId", "t": "string", "in": "body", "r": True},
            {"n": "sharedWithOrganization", "t": "boolean", "in": "body", "r": True},
        ],
    },
    {
        "tag": "gitea",
        "m": "POST",
        "p": "/gitea.create",
        "params": [
            {"n": "giteaId", "t": "string", "in": "body"},
            {"n": "giteaUrl", "t": "string", "in": "body", "r": True},
            {"n": "giteaInternalUrl", "t": "string", "in": "body"},
            {"n": "redirectUri", "t": "string", "in": "body"},
            {"n": "clientId", "t": "string", "in": "body"},
            {"n": "clientSecret", "t": "string", "in": "body"},
            {"n": "gitProviderId", "t": "string", "in": "body"},
            {"n": "accessToken", "t": "string", "in": "body"},
            {"n": "refreshToken", "t": "string", "in": "body"},
            {"n": "expiresAt", "t": "number", "in": "body"},
            {"n": "scopes", "t": "string", "in": "body"},
            {"n": "lastAuthenticatedAt", "t": "number", "in": "body"},
            {"n": "name", "t": "string", "in": "body", "r": True},
            {"n": "giteaUsername", "t": "string", "in": "body"},
            {"n": "organizationName", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "gitea",
        "m": "GET",
        "p": "/gitea.getGiteaBranches",
        "params": [
            {"n": "owner", "t": "string", "in": "query", "r": True},
            {"n": "repositoryName", "t": "string", "in": "query", "r": True},
            {"n": "giteaId", "t": "string", "in": "query"},
        ],
    },
    {
        "tag": "gitea",
        "m": "GET",
        "p": "/gitea.getGiteaRepositories",
        "params": [
            {"n": "giteaId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "gitea",
        "m": "GET",
        "p": "/gitea.getGiteaUrl",
        "params": [
            {"n": "giteaId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "gitea",
        "m": "GET",
        "p": "/gitea.giteaProviders",
        "params": [],
    },
    {
        "tag": "gitea",
        "m": "GET",
        "p": "/gitea.one",
        "params": [
            {"n": "giteaId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "gitea",
        "m": "POST",
        "p": "/gitea.testConnection",
        "params": [
            {"n": "giteaId", "t": "string", "in": "body"},
            {"n": "organizationName", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "gitea",
        "m": "POST",
        "p": "/gitea.update",
        "params": [
            {"n": "giteaId", "t": "string", "in": "body", "r": True},
            {"n": "giteaUrl", "t": "string", "in": "body", "r": True},
            {"n": "giteaInternalUrl", "t": "string", "in": "body"},
            {"n": "redirectUri", "t": "string", "in": "body"},
            {"n": "clientId", "t": "string", "in": "body"},
            {"n": "clientSecret", "t": "string", "in": "body"},
            {"n": "gitProviderId", "t": "string", "in": "body", "r": True},
            {"n": "accessToken", "t": "string", "in": "body"},
            {"n": "refreshToken", "t": "string", "in": "body"},
            {"n": "expiresAt", "t": "number", "in": "body"},
            {"n": "scopes", "t": "string", "in": "body"},
            {"n": "lastAuthenticatedAt", "t": "number", "in": "body"},
            {"n": "name", "t": "string", "in": "body", "r": True},
            {"n": "giteaUsername", "t": "string", "in": "body"},
            {"n": "organizationName", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "github",
        "m": "GET",
        "p": "/github.getGithubBranches",
        "params": [
            {"n": "repo", "t": "string", "in": "query", "r": True},
            {"n": "owner", "t": "string", "in": "query", "r": True},
            {"n": "githubId", "t": "string", "in": "query"},
        ],
    },
    {
        "tag": "github",
        "m": "GET",
        "p": "/github.getGithubRepositories",
        "params": [
            {"n": "githubId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "github",
        "m": "GET",
        "p": "/github.githubProviders",
        "params": [],
    },
    {
        "tag": "github",
        "m": "GET",
        "p": "/github.one",
        "params": [
            {"n": "githubId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "github",
        "m": "POST",
        "p": "/github.testConnection",
        "params": [
            {"n": "githubId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "github",
        "m": "POST",
        "p": "/github.update",
        "params": [
            {"n": "githubId", "t": "string", "in": "body", "r": True},
            {"n": "name", "t": "string", "in": "body", "r": True},
            {"n": "gitProviderId", "t": "string", "in": "body", "r": True},
            {"n": "githubAppName", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "gitlab",
        "m": "POST",
        "p": "/gitlab.create",
        "params": [
            {"n": "applicationId", "t": "string", "in": "body"},
            {"n": "secret", "t": "string", "in": "body"},
            {"n": "groupName", "t": "string", "in": "body"},
            {"n": "gitProviderId", "t": "string", "in": "body"},
            {"n": "redirectUri", "t": "string", "in": "body"},
            {"n": "authId", "t": "string", "in": "body", "r": True},
            {"n": "name", "t": "string", "in": "body", "r": True},
            {"n": "gitlabUrl", "t": "string", "in": "body", "r": True},
            {"n": "gitlabInternalUrl", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "gitlab",
        "m": "GET",
        "p": "/gitlab.getGitlabBranches",
        "params": [
            {"n": "id", "t": "number", "in": "query"},
            {"n": "owner", "t": "string", "in": "query", "r": True},
            {"n": "repo", "t": "string", "in": "query", "r": True},
            {"n": "gitlabId", "t": "string", "in": "query"},
        ],
    },
    {
        "tag": "gitlab",
        "m": "GET",
        "p": "/gitlab.getGitlabRepositories",
        "params": [
            {"n": "gitlabId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "gitlab",
        "m": "GET",
        "p": "/gitlab.gitlabProviders",
        "params": [],
    },
    {
        "tag": "gitlab",
        "m": "GET",
        "p": "/gitlab.one",
        "params": [
            {"n": "gitlabId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "gitlab",
        "m": "POST",
        "p": "/gitlab.testConnection",
        "params": [
            {"n": "gitlabId", "t": "string", "in": "body", "r": True},
            {"n": "groupName", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "gitlab",
        "m": "POST",
        "p": "/gitlab.update",
        "params": [
            {"n": "applicationId", "t": "string", "in": "body"},
            {"n": "secret", "t": "string", "in": "body"},
            {"n": "groupName", "t": "string", "in": "body"},
            {"n": "redirectUri", "t": "string", "in": "body"},
            {"n": "name", "t": "string", "in": "body", "r": True},
            {"n": "gitlabId", "t": "string", "in": "body", "r": True},
            {"n": "gitlabUrl", "t": "string", "in": "body", "r": True},
            {"n": "gitProviderId", "t": "string", "in": "body", "r": True},
            {"n": "gitlabInternalUrl", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "libsql",
        "m": "POST",
        "p": "/libsql.changeStatus",
        "params": [
            {"n": "libsqlId", "t": "string", "in": "body", "r": True},
            {"n": "applicationStatus", "t": "string", "in": "body", "r": True, "e": ["idle", "running", "done", "error"]},
        ],
    },
    {
        "tag": "libsql",
        "m": "POST",
        "p": "/libsql.create",
        "params": [
            {"n": "name", "t": "string", "in": "body", "r": True},
            {"n": "appName", "t": "string", "in": "body", "r": True},
            {"n": "dockerImage", "t": "string", "in": "body", "r": True},
            {"n": "environmentId", "t": "string", "in": "body", "r": True},
            {"n": "description", "t": "string", "in": "body", "r": True},
            {"n": "databaseUser", "t": "string", "in": "body", "r": True},
            {"n": "databasePassword", "t": "string", "in": "body", "r": True},
            {"n": "sqldNode", "t": "string", "in": "body", "r": True, "e": ["primary", "replica"]},
            {"n": "sqldPrimaryUrl", "t": "string", "in": "body", "r": True},
            {"n": "enableNamespaces", "t": "boolean", "in": "body", "r": True},
            {"n": "serverId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "libsql",
        "m": "POST",
        "p": "/libsql.deploy",
        "params": [
            {"n": "libsqlId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "libsql",
        "m": "POST",
        "p": "/libsql.move",
        "params": [
            {"n": "libsqlId", "t": "string", "in": "body", "r": True},
            {"n": "targetEnvironmentId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "libsql",
        "m": "GET",
        "p": "/libsql.one",
        "params": [
            {"n": "libsqlId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "libsql",
        "m": "GET",
        "p": "/libsql.readLogs",
        "params": [
            {"n": "libsqlId", "t": "string", "in": "query", "r": True},
            {"n": "tail", "t": "integer", "in": "query"},
            {"n": "since", "t": "string", "in": "query"},
            {"n": "search", "t": "string", "in": "query"},
        ],
    },
    {
        "tag": "libsql",
        "m": "POST",
        "p": "/libsql.rebuild",
        "params": [
            {"n": "libsqlId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "libsql",
        "m": "POST",
        "p": "/libsql.reload",
        "params": [
            {"n": "libsqlId", "t": "string", "in": "body", "r": True},
            {"n": "appName", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "libsql",
        "m": "POST",
        "p": "/libsql.remove",
        "params": [
            {"n": "libsqlId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "libsql",
        "m": "POST",
        "p": "/libsql.saveEnvironment",
        "params": [
            {"n": "libsqlId", "t": "string", "in": "body", "r": True},
            {"n": "env", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "libsql",
        "m": "POST",
        "p": "/libsql.saveExternalPorts",
        "params": [
            {"n": "libsqlId", "t": "string", "in": "body", "r": True},
            {"n": "externalPort", "t": "number", "in": "body"},
            {"n": "externalGRPCPort", "t": "number", "in": "body"},
            {"n": "externalAdminPort", "t": "number", "in": "body"},
        ],
    },
    {
        "tag": "libsql",
        "m": "POST",
        "p": "/libsql.start",
        "params": [
            {"n": "libsqlId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "libsql",
        "m": "POST",
        "p": "/libsql.stop",
        "params": [
            {"n": "libsqlId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "libsql",
        "m": "POST",
        "p": "/libsql.update",
        "params": [
            {"n": "libsqlId", "t": "string", "in": "body", "r": True},
            {"n": "name", "t": "string", "in": "body"},
            {"n": "appName", "t": "string", "in": "body"},
            {"n": "description", "t": "string", "in": "body"},
            {"n": "databaseUser", "t": "string", "in": "body"},
            {"n": "databasePassword", "t": "string", "in": "body"},
            {"n": "sqldNode", "t": "string", "in": "body", "e": ["primary", "replica"]},
            {"n": "sqldPrimaryUrl", "t": "string", "in": "body"},
            {"n": "enableNamespaces", "t": "boolean", "in": "body"},
            {"n": "dockerImage", "t": "string", "in": "body"},
            {"n": "command", "t": "string", "in": "body"},
            {"n": "env", "t": "string", "in": "body"},
            {"n": "memoryReservation", "t": "string", "in": "body"},
            {"n": "memoryLimit", "t": "string", "in": "body"},
            {"n": "cpuReservation", "t": "string", "in": "body"},
            {"n": "cpuLimit", "t": "string", "in": "body"},
            {"n": "externalPort", "t": "number", "in": "body"},
            {"n": "externalGRPCPort", "t": "number", "in": "body"},
            {"n": "externalAdminPort", "t": "number", "in": "body"},
            {"n": "applicationStatus", "t": "string", "in": "body", "e": ["idle", "running", "done", "error"]},
            {"n": "healthCheckSwarm", "t": "object", "in": "body"},
            {"n": "restartPolicySwarm", "t": "object", "in": "body"},
            {"n": "placementSwarm", "t": "object", "in": "body"},
            {"n": "updateConfigSwarm", "t": "object", "in": "body"},
            {"n": "rollbackConfigSwarm", "t": "object", "in": "body"},
            {"n": "modeSwarm", "t": "object", "in": "body"},
            {"n": "labelsSwarm", "t": "object", "in": "body"},
            {"n": "networkSwarm", "t": "array", "in": "body"},
            {"n": "stopGracePeriodSwarm", "t": "number", "in": "body"},
            {"n": "endpointSpecSwarm", "t": "object", "in": "body"},
            {"n": "replicas", "t": "number", "in": "body"},
            {"n": "createdAt", "t": "string", "in": "body"},
            {"n": "environmentId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "licenseKey",
        "m": "POST",
        "p": "/licenseKey.activate",
        "params": [
            {"n": "licenseKey", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "licenseKey",
        "m": "POST",
        "p": "/licenseKey.deactivate",
        "params": [],
    },
    {
        "tag": "licenseKey",
        "m": "GET",
        "p": "/licenseKey.getEnterpriseSettings",
        "params": [],
    },
    {
        "tag": "licenseKey",
        "m": "GET",
        "p": "/licenseKey.haveValidLicenseKey",
        "params": [],
    },
    {
        "tag": "licenseKey",
        "m": "POST",
        "p": "/licenseKey.updateEnterpriseSettings",
        "params": [
            {"n": "enableEnterpriseFeatures", "t": "boolean", "in": "body"},
        ],
    },
    {
        "tag": "licenseKey",
        "m": "POST",
        "p": "/licenseKey.validate",
        "params": [],
    },
    {
        "tag": "mariadb",
        "m": "POST",
        "p": "/mariadb.changePassword",
        "params": [
            {"n": "mariadbId", "t": "string", "in": "body", "r": True},
            {"n": "password", "t": "string", "in": "body", "r": True},
            {"n": "type", "t": "string", "in": "body", "e": ["user", "root"]},
        ],
    },
    {
        "tag": "mariadb",
        "m": "POST",
        "p": "/mariadb.changeStatus",
        "params": [
            {"n": "mariadbId", "t": "string", "in": "body", "r": True},
            {"n": "applicationStatus", "t": "string", "in": "body", "r": True, "e": ["idle", "running", "done", "error"]},
        ],
    },
    {
        "tag": "mariadb",
        "m": "POST",
        "p": "/mariadb.create",
        "params": [
            {"n": "name", "t": "string", "in": "body", "r": True},
            {"n": "appName", "t": "string", "in": "body"},
            {"n": "dockerImage", "t": "string", "in": "body"},
            {"n": "databaseRootPassword", "t": "string", "in": "body"},
            {"n": "environmentId", "t": "string", "in": "body", "r": True},
            {"n": "description", "t": "string", "in": "body"},
            {"n": "databaseName", "t": "string", "in": "body", "r": True},
            {"n": "databaseUser", "t": "string", "in": "body", "r": True},
            {"n": "databasePassword", "t": "string", "in": "body", "r": True},
            {"n": "serverId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "mariadb",
        "m": "POST",
        "p": "/mariadb.deploy",
        "params": [
            {"n": "mariadbId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "mariadb",
        "m": "POST",
        "p": "/mariadb.move",
        "params": [
            {"n": "mariadbId", "t": "string", "in": "body", "r": True},
            {"n": "targetEnvironmentId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "mariadb",
        "m": "GET",
        "p": "/mariadb.one",
        "params": [
            {"n": "mariadbId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "mariadb",
        "m": "GET",
        "p": "/mariadb.readLogs",
        "params": [
            {"n": "mariadbId", "t": "string", "in": "query", "r": True},
            {"n": "tail", "t": "integer", "in": "query"},
            {"n": "since", "t": "string", "in": "query"},
            {"n": "search", "t": "string", "in": "query"},
        ],
    },
    {
        "tag": "mariadb",
        "m": "POST",
        "p": "/mariadb.rebuild",
        "params": [
            {"n": "mariadbId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "mariadb",
        "m": "POST",
        "p": "/mariadb.reload",
        "params": [
            {"n": "mariadbId", "t": "string", "in": "body", "r": True},
            {"n": "appName", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "mariadb",
        "m": "POST",
        "p": "/mariadb.remove",
        "params": [
            {"n": "mariadbId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "mariadb",
        "m": "POST",
        "p": "/mariadb.saveEnvironment",
        "params": [
            {"n": "mariadbId", "t": "string", "in": "body", "r": True},
            {"n": "env", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "mariadb",
        "m": "POST",
        "p": "/mariadb.saveExternalPort",
        "params": [
            {"n": "mariadbId", "t": "string", "in": "body", "r": True},
            {"n": "externalPort", "t": "number", "in": "body", "r": True},
        ],
    },
    {
        "tag": "mariadb",
        "m": "GET",
        "p": "/mariadb.search",
        "params": [
            {"n": "q", "t": "string", "in": "query"},
            {"n": "name", "t": "string", "in": "query"},
            {"n": "appName", "t": "string", "in": "query"},
            {"n": "description", "t": "string", "in": "query"},
            {"n": "projectId", "t": "string", "in": "query"},
            {"n": "environmentId", "t": "string", "in": "query"},
            {"n": "limit", "t": "number", "in": "query"},
            {"n": "offset", "t": "number", "in": "query"},
        ],
    },
    {
        "tag": "mariadb",
        "m": "POST",
        "p": "/mariadb.start",
        "params": [
            {"n": "mariadbId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "mariadb",
        "m": "POST",
        "p": "/mariadb.stop",
        "params": [
            {"n": "mariadbId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "mariadb",
        "m": "POST",
        "p": "/mariadb.update",
        "params": [
            {"n": "mariadbId", "t": "string", "in": "body", "r": True},
            {"n": "name", "t": "string", "in": "body"},
            {"n": "appName", "t": "string", "in": "body"},
            {"n": "description", "t": "string", "in": "body"},
            {"n": "databaseName", "t": "string", "in": "body"},
            {"n": "databaseUser", "t": "string", "in": "body"},
            {"n": "databasePassword", "t": "string", "in": "body"},
            {"n": "databaseRootPassword", "t": "string", "in": "body"},
            {"n": "dockerImage", "t": "string", "in": "body"},
            {"n": "command", "t": "string", "in": "body"},
            {"n": "args", "t": "array", "in": "body"},
            {"n": "env", "t": "string", "in": "body"},
            {"n": "memoryReservation", "t": "string", "in": "body"},
            {"n": "memoryLimit", "t": "string", "in": "body"},
            {"n": "cpuReservation", "t": "string", "in": "body"},
            {"n": "cpuLimit", "t": "string", "in": "body"},
            {"n": "externalPort", "t": "number", "in": "body"},
            {"n": "applicationStatus", "t": "string", "in": "body", "e": ["idle", "running", "done", "error"]},
            {"n": "healthCheckSwarm", "t": "object", "in": "body"},
            {"n": "restartPolicySwarm", "t": "object", "in": "body"},
            {"n": "placementSwarm", "t": "object", "in": "body"},
            {"n": "updateConfigSwarm", "t": "object", "in": "body"},
            {"n": "rollbackConfigSwarm", "t": "object", "in": "body"},
            {"n": "modeSwarm", "t": "object", "in": "body"},
            {"n": "labelsSwarm", "t": "object", "in": "body"},
            {"n": "networkSwarm", "t": "array", "in": "body"},
            {"n": "stopGracePeriodSwarm", "t": "number", "in": "body"},
            {"n": "endpointSpecSwarm", "t": "object", "in": "body"},
            {"n": "ulimitsSwarm", "t": "array", "in": "body"},
            {"n": "replicas", "t": "number", "in": "body"},
            {"n": "createdAt", "t": "string", "in": "body"},
            {"n": "environmentId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "mongo",
        "m": "POST",
        "p": "/mongo.changePassword",
        "params": [
            {"n": "mongoId", "t": "string", "in": "body", "r": True},
            {"n": "password", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "mongo",
        "m": "POST",
        "p": "/mongo.changeStatus",
        "params": [
            {"n": "mongoId", "t": "string", "in": "body", "r": True},
            {"n": "applicationStatus", "t": "string", "in": "body", "r": True, "e": ["idle", "running", "done", "error"]},
        ],
    },
    {
        "tag": "mongo",
        "m": "POST",
        "p": "/mongo.create",
        "params": [
            {"n": "name", "t": "string", "in": "body", "r": True},
            {"n": "appName", "t": "string", "in": "body"},
            {"n": "dockerImage", "t": "string", "in": "body"},
            {"n": "environmentId", "t": "string", "in": "body", "r": True},
            {"n": "description", "t": "string", "in": "body"},
            {"n": "databaseUser", "t": "string", "in": "body", "r": True},
            {"n": "databasePassword", "t": "string", "in": "body", "r": True},
            {"n": "serverId", "t": "string", "in": "body"},
            {"n": "replicaSets", "t": "boolean", "in": "body"},
        ],
    },
    {
        "tag": "mongo",
        "m": "POST",
        "p": "/mongo.deploy",
        "params": [
            {"n": "mongoId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "mongo",
        "m": "POST",
        "p": "/mongo.move",
        "params": [
            {"n": "mongoId", "t": "string", "in": "body", "r": True},
            {"n": "targetEnvironmentId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "mongo",
        "m": "GET",
        "p": "/mongo.one",
        "params": [
            {"n": "mongoId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "mongo",
        "m": "GET",
        "p": "/mongo.readLogs",
        "params": [
            {"n": "mongoId", "t": "string", "in": "query", "r": True},
            {"n": "tail", "t": "integer", "in": "query"},
            {"n": "since", "t": "string", "in": "query"},
            {"n": "search", "t": "string", "in": "query"},
        ],
    },
    {
        "tag": "mongo",
        "m": "POST",
        "p": "/mongo.rebuild",
        "params": [
            {"n": "mongoId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "mongo",
        "m": "POST",
        "p": "/mongo.reload",
        "params": [
            {"n": "mongoId", "t": "string", "in": "body", "r": True},
            {"n": "appName", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "mongo",
        "m": "POST",
        "p": "/mongo.remove",
        "params": [
            {"n": "mongoId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "mongo",
        "m": "POST",
        "p": "/mongo.saveEnvironment",
        "params": [
            {"n": "mongoId", "t": "string", "in": "body", "r": True},
            {"n": "env", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "mongo",
        "m": "POST",
        "p": "/mongo.saveExternalPort",
        "params": [
            {"n": "mongoId", "t": "string", "in": "body", "r": True},
            {"n": "externalPort", "t": "number", "in": "body", "r": True},
        ],
    },
    {
        "tag": "mongo",
        "m": "GET",
        "p": "/mongo.search",
        "params": [
            {"n": "q", "t": "string", "in": "query"},
            {"n": "name", "t": "string", "in": "query"},
            {"n": "appName", "t": "string", "in": "query"},
            {"n": "description", "t": "string", "in": "query"},
            {"n": "projectId", "t": "string", "in": "query"},
            {"n": "environmentId", "t": "string", "in": "query"},
            {"n": "limit", "t": "number", "in": "query"},
            {"n": "offset", "t": "number", "in": "query"},
        ],
    },
    {
        "tag": "mongo",
        "m": "POST",
        "p": "/mongo.start",
        "params": [
            {"n": "mongoId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "mongo",
        "m": "POST",
        "p": "/mongo.stop",
        "params": [
            {"n": "mongoId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "mongo",
        "m": "POST",
        "p": "/mongo.update",
        "params": [
            {"n": "mongoId", "t": "string", "in": "body", "r": True},
            {"n": "name", "t": "string", "in": "body"},
            {"n": "appName", "t": "string", "in": "body"},
            {"n": "description", "t": "string", "in": "body"},
            {"n": "databaseUser", "t": "string", "in": "body"},
            {"n": "databasePassword", "t": "string", "in": "body"},
            {"n": "dockerImage", "t": "string", "in": "body"},
            {"n": "command", "t": "string", "in": "body"},
            {"n": "args", "t": "array", "in": "body"},
            {"n": "env", "t": "string", "in": "body"},
            {"n": "memoryReservation", "t": "string", "in": "body"},
            {"n": "memoryLimit", "t": "string", "in": "body"},
            {"n": "cpuReservation", "t": "string", "in": "body"},
            {"n": "cpuLimit", "t": "string", "in": "body"},
            {"n": "externalPort", "t": "number", "in": "body"},
            {"n": "applicationStatus", "t": "string", "in": "body", "e": ["idle", "running", "done", "error"]},
            {"n": "healthCheckSwarm", "t": "object", "in": "body"},
            {"n": "restartPolicySwarm", "t": "object", "in": "body"},
            {"n": "placementSwarm", "t": "object", "in": "body"},
            {"n": "updateConfigSwarm", "t": "object", "in": "body"},
            {"n": "rollbackConfigSwarm", "t": "object", "in": "body"},
            {"n": "modeSwarm", "t": "object", "in": "body"},
            {"n": "labelsSwarm", "t": "object", "in": "body"},
            {"n": "networkSwarm", "t": "array", "in": "body"},
            {"n": "stopGracePeriodSwarm", "t": "number", "in": "body"},
            {"n": "endpointSpecSwarm", "t": "object", "in": "body"},
            {"n": "ulimitsSwarm", "t": "array", "in": "body"},
            {"n": "replicas", "t": "number", "in": "body"},
            {"n": "createdAt", "t": "string", "in": "body"},
            {"n": "environmentId", "t": "string", "in": "body"},
            {"n": "replicaSets", "t": "boolean", "in": "body"},
        ],
    },
    {
        "tag": "mounts",
        "m": "GET",
        "p": "/mounts.allNamedByApplicationId",
        "params": [
            {"n": "applicationId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "mounts",
        "m": "POST",
        "p": "/mounts.create",
        "params": [
            {"n": "type", "t": "string", "in": "body", "r": True, "e": ["bind", "volume", "file"]},
            {"n": "hostPath", "t": "string", "in": "body"},
            {"n": "volumeName", "t": "string", "in": "body"},
            {"n": "content", "t": "string", "in": "body"},
            {"n": "mountPath", "t": "string", "in": "body", "r": True},
            {"n": "filePath", "t": "string", "in": "body"},
            {"n": "serviceType", "t": "string", "in": "body", "e": ["application", "postgres", "mysql", "mariadb", "mongo", "redis", "compose", "libsql"]},
            {"n": "serviceId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "mounts",
        "m": "GET",
        "p": "/mounts.listByServiceId",
        "params": [
            {"n": "serviceType", "t": "string", "in": "query", "r": True},
            {"n": "serviceId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "mounts",
        "m": "GET",
        "p": "/mounts.one",
        "params": [
            {"n": "mountId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "mounts",
        "m": "POST",
        "p": "/mounts.remove",
        "params": [
            {"n": "mountId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "mounts",
        "m": "POST",
        "p": "/mounts.update",
        "params": [
            {"n": "mountId", "t": "string", "in": "body", "r": True},
            {"n": "type", "t": "string", "in": "body", "e": ["bind", "volume", "file"]},
            {"n": "hostPath", "t": "string", "in": "body"},
            {"n": "volumeName", "t": "string", "in": "body"},
            {"n": "filePath", "t": "string", "in": "body"},
            {"n": "content", "t": "string", "in": "body"},
            {"n": "serviceType", "t": "string", "in": "body", "e": ["application", "postgres", "mysql", "mariadb", "mongo", "redis", "compose", "libsql"]},
            {"n": "mountPath", "t": "string", "in": "body"},
            {"n": "applicationId", "t": "string", "in": "body"},
            {"n": "composeId", "t": "string", "in": "body"},
            {"n": "libsqlId", "t": "string", "in": "body"},
            {"n": "mariadbId", "t": "string", "in": "body"},
            {"n": "mongoId", "t": "string", "in": "body"},
            {"n": "mysqlId", "t": "string", "in": "body"},
            {"n": "postgresId", "t": "string", "in": "body"},
            {"n": "redisId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "mysql",
        "m": "POST",
        "p": "/mysql.changePassword",
        "params": [
            {"n": "mysqlId", "t": "string", "in": "body", "r": True},
            {"n": "password", "t": "string", "in": "body", "r": True},
            {"n": "type", "t": "string", "in": "body", "e": ["user", "root"]},
        ],
    },
    {
        "tag": "mysql",
        "m": "POST",
        "p": "/mysql.changeStatus",
        "params": [
            {"n": "mysqlId", "t": "string", "in": "body", "r": True},
            {"n": "applicationStatus", "t": "string", "in": "body", "r": True, "e": ["idle", "running", "done", "error"]},
        ],
    },
    {
        "tag": "mysql",
        "m": "POST",
        "p": "/mysql.create",
        "params": [
            {"n": "name", "t": "string", "in": "body", "r": True},
            {"n": "appName", "t": "string", "in": "body"},
            {"n": "dockerImage", "t": "string", "in": "body"},
            {"n": "environmentId", "t": "string", "in": "body", "r": True},
            {"n": "description", "t": "string", "in": "body"},
            {"n": "databaseName", "t": "string", "in": "body", "r": True},
            {"n": "databaseUser", "t": "string", "in": "body", "r": True},
            {"n": "databasePassword", "t": "string", "in": "body", "r": True},
            {"n": "databaseRootPassword", "t": "string", "in": "body"},
            {"n": "serverId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "mysql",
        "m": "POST",
        "p": "/mysql.deploy",
        "params": [
            {"n": "mysqlId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "mysql",
        "m": "POST",
        "p": "/mysql.move",
        "params": [
            {"n": "mysqlId", "t": "string", "in": "body", "r": True},
            {"n": "targetEnvironmentId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "mysql",
        "m": "GET",
        "p": "/mysql.one",
        "params": [
            {"n": "mysqlId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "mysql",
        "m": "GET",
        "p": "/mysql.readLogs",
        "params": [
            {"n": "mysqlId", "t": "string", "in": "query", "r": True},
            {"n": "tail", "t": "integer", "in": "query"},
            {"n": "since", "t": "string", "in": "query"},
            {"n": "search", "t": "string", "in": "query"},
        ],
    },
    {
        "tag": "mysql",
        "m": "POST",
        "p": "/mysql.rebuild",
        "params": [
            {"n": "mysqlId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "mysql",
        "m": "POST",
        "p": "/mysql.reload",
        "params": [
            {"n": "mysqlId", "t": "string", "in": "body", "r": True},
            {"n": "appName", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "mysql",
        "m": "POST",
        "p": "/mysql.remove",
        "params": [
            {"n": "mysqlId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "mysql",
        "m": "POST",
        "p": "/mysql.saveEnvironment",
        "params": [
            {"n": "mysqlId", "t": "string", "in": "body", "r": True},
            {"n": "env", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "mysql",
        "m": "POST",
        "p": "/mysql.saveExternalPort",
        "params": [
            {"n": "mysqlId", "t": "string", "in": "body", "r": True},
            {"n": "externalPort", "t": "number", "in": "body", "r": True},
        ],
    },
    {
        "tag": "mysql",
        "m": "GET",
        "p": "/mysql.search",
        "params": [
            {"n": "q", "t": "string", "in": "query"},
            {"n": "name", "t": "string", "in": "query"},
            {"n": "appName", "t": "string", "in": "query"},
            {"n": "description", "t": "string", "in": "query"},
            {"n": "projectId", "t": "string", "in": "query"},
            {"n": "environmentId", "t": "string", "in": "query"},
            {"n": "limit", "t": "number", "in": "query"},
            {"n": "offset", "t": "number", "in": "query"},
        ],
    },
    {
        "tag": "mysql",
        "m": "POST",
        "p": "/mysql.start",
        "params": [
            {"n": "mysqlId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "mysql",
        "m": "POST",
        "p": "/mysql.stop",
        "params": [
            {"n": "mysqlId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "mysql",
        "m": "POST",
        "p": "/mysql.update",
        "params": [
            {"n": "mysqlId", "t": "string", "in": "body", "r": True},
            {"n": "name", "t": "string", "in": "body"},
            {"n": "appName", "t": "string", "in": "body"},
            {"n": "description", "t": "string", "in": "body"},
            {"n": "databaseName", "t": "string", "in": "body"},
            {"n": "databaseUser", "t": "string", "in": "body"},
            {"n": "databasePassword", "t": "string", "in": "body"},
            {"n": "databaseRootPassword", "t": "string", "in": "body"},
            {"n": "dockerImage", "t": "string", "in": "body"},
            {"n": "command", "t": "string", "in": "body"},
            {"n": "args", "t": "array", "in": "body"},
            {"n": "env", "t": "string", "in": "body"},
            {"n": "memoryReservation", "t": "string", "in": "body"},
            {"n": "memoryLimit", "t": "string", "in": "body"},
            {"n": "cpuReservation", "t": "string", "in": "body"},
            {"n": "cpuLimit", "t": "string", "in": "body"},
            {"n": "externalPort", "t": "number", "in": "body"},
            {"n": "applicationStatus", "t": "string", "in": "body", "e": ["idle", "running", "done", "error"]},
            {"n": "healthCheckSwarm", "t": "object", "in": "body"},
            {"n": "restartPolicySwarm", "t": "object", "in": "body"},
            {"n": "placementSwarm", "t": "object", "in": "body"},
            {"n": "updateConfigSwarm", "t": "object", "in": "body"},
            {"n": "rollbackConfigSwarm", "t": "object", "in": "body"},
            {"n": "modeSwarm", "t": "object", "in": "body"},
            {"n": "labelsSwarm", "t": "object", "in": "body"},
            {"n": "networkSwarm", "t": "array", "in": "body"},
            {"n": "stopGracePeriodSwarm", "t": "number", "in": "body"},
            {"n": "endpointSpecSwarm", "t": "object", "in": "body"},
            {"n": "ulimitsSwarm", "t": "array", "in": "body"},
            {"n": "replicas", "t": "number", "in": "body"},
            {"n": "createdAt", "t": "string", "in": "body"},
            {"n": "environmentId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "notification",
        "m": "GET",
        "p": "/notification.all",
        "params": [],
    },
    {
        "tag": "notification",
        "m": "POST",
        "p": "/notification.createCustom",
        "params": [
            {"n": "appBuildError", "t": "boolean", "in": "body"},
            {"n": "databaseBackup", "t": "boolean", "in": "body"},
            {"n": "dokployBackup", "t": "boolean", "in": "body"},
            {"n": "volumeBackup", "t": "boolean", "in": "body"},
            {"n": "dokployRestart", "t": "boolean", "in": "body"},
            {"n": "name", "t": "string", "in": "body", "r": True},
            {"n": "appDeploy", "t": "boolean", "in": "body"},
            {"n": "dockerCleanup", "t": "boolean", "in": "body"},
            {"n": "serverThreshold", "t": "boolean", "in": "body"},
            {"n": "endpoint", "t": "string", "in": "body", "r": True},
            {"n": "headers", "t": "object", "in": "body"},
        ],
    },
    {
        "tag": "notification",
        "m": "POST",
        "p": "/notification.createDiscord",
        "params": [
            {"n": "appBuildError", "t": "boolean", "in": "body", "r": True},
            {"n": "databaseBackup", "t": "boolean", "in": "body", "r": True},
            {"n": "dokployBackup", "t": "boolean", "in": "body", "r": True},
            {"n": "volumeBackup", "t": "boolean", "in": "body", "r": True},
            {"n": "dokployRestart", "t": "boolean", "in": "body", "r": True},
            {"n": "name", "t": "string", "in": "body", "r": True},
            {"n": "appDeploy", "t": "boolean", "in": "body", "r": True},
            {"n": "dockerCleanup", "t": "boolean", "in": "body", "r": True},
            {"n": "serverThreshold", "t": "boolean", "in": "body", "r": True},
            {"n": "webhookUrl", "t": "string", "in": "body", "r": True},
            {"n": "decoration", "t": "boolean", "in": "body", "r": True},
        ],
    },
    {
        "tag": "notification",
        "m": "POST",
        "p": "/notification.createEmail",
        "params": [
            {"n": "appBuildError", "t": "boolean", "in": "body", "r": True},
            {"n": "databaseBackup", "t": "boolean", "in": "body", "r": True},
            {"n": "dokployBackup", "t": "boolean", "in": "body", "r": True},
            {"n": "volumeBackup", "t": "boolean", "in": "body", "r": True},
            {"n": "dokployRestart", "t": "boolean", "in": "body", "r": True},
            {"n": "name", "t": "string", "in": "body", "r": True},
            {"n": "appDeploy", "t": "boolean", "in": "body", "r": True},
            {"n": "dockerCleanup", "t": "boolean", "in": "body", "r": True},
            {"n": "serverThreshold", "t": "boolean", "in": "body", "r": True},
            {"n": "smtpServer", "t": "string", "in": "body", "r": True},
            {"n": "smtpPort", "t": "number", "in": "body", "r": True},
            {"n": "username", "t": "string", "in": "body", "r": True},
            {"n": "password", "t": "string", "in": "body", "r": True},
            {"n": "fromAddress", "t": "string", "in": "body", "r": True},
            {"n": "toAddresses", "t": "array", "in": "body", "r": True},
        ],
    },
    {
        "tag": "notification",
        "m": "POST",
        "p": "/notification.createGotify",
        "params": [
            {"n": "appBuildError", "t": "boolean", "in": "body", "r": True},
            {"n": "databaseBackup", "t": "boolean", "in": "body", "r": True},
            {"n": "dokployBackup", "t": "boolean", "in": "body", "r": True},
            {"n": "volumeBackup", "t": "boolean", "in": "body", "r": True},
            {"n": "dokployRestart", "t": "boolean", "in": "body", "r": True},
            {"n": "name", "t": "string", "in": "body", "r": True},
            {"n": "appDeploy", "t": "boolean", "in": "body", "r": True},
            {"n": "dockerCleanup", "t": "boolean", "in": "body", "r": True},
            {"n": "serverUrl", "t": "string", "in": "body", "r": True},
            {"n": "appToken", "t": "string", "in": "body", "r": True},
            {"n": "priority", "t": "number", "in": "body", "r": True},
            {"n": "decoration", "t": "boolean", "in": "body", "r": True},
        ],
    },
    {
        "tag": "notification",
        "m": "POST",
        "p": "/notification.createLark",
        "params": [
            {"n": "appBuildError", "t": "boolean", "in": "body", "r": True},
            {"n": "databaseBackup", "t": "boolean", "in": "body", "r": True},
            {"n": "dokployBackup", "t": "boolean", "in": "body", "r": True},
            {"n": "volumeBackup", "t": "boolean", "in": "body", "r": True},
            {"n": "dokployRestart", "t": "boolean", "in": "body", "r": True},
            {"n": "name", "t": "string", "in": "body", "r": True},
            {"n": "appDeploy", "t": "boolean", "in": "body", "r": True},
            {"n": "dockerCleanup", "t": "boolean", "in": "body", "r": True},
            {"n": "serverThreshold", "t": "boolean", "in": "body", "r": True},
            {"n": "webhookUrl", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "notification",
        "m": "POST",
        "p": "/notification.createMattermost",
        "params": [
            {"n": "appBuildError", "t": "boolean", "in": "body", "r": True},
            {"n": "databaseBackup", "t": "boolean", "in": "body", "r": True},
            {"n": "dokployBackup", "t": "boolean", "in": "body", "r": True},
            {"n": "volumeBackup", "t": "boolean", "in": "body", "r": True},
            {"n": "dokployRestart", "t": "boolean", "in": "body", "r": True},
            {"n": "name", "t": "string", "in": "body", "r": True},
            {"n": "appDeploy", "t": "boolean", "in": "body", "r": True},
            {"n": "dockerCleanup", "t": "boolean", "in": "body", "r": True},
            {"n": "serverThreshold", "t": "boolean", "in": "body", "r": True},
            {"n": "webhookUrl", "t": "string", "in": "body", "r": True},
            {"n": "channel", "t": "string", "in": "body"},
            {"n": "username", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "notification",
        "m": "POST",
        "p": "/notification.createNtfy",
        "params": [
            {"n": "appBuildError", "t": "boolean", "in": "body", "r": True},
            {"n": "databaseBackup", "t": "boolean", "in": "body", "r": True},
            {"n": "dokployBackup", "t": "boolean", "in": "body", "r": True},
            {"n": "volumeBackup", "t": "boolean", "in": "body", "r": True},
            {"n": "dokployRestart", "t": "boolean", "in": "body", "r": True},
            {"n": "name", "t": "string", "in": "body", "r": True},
            {"n": "appDeploy", "t": "boolean", "in": "body", "r": True},
            {"n": "dockerCleanup", "t": "boolean", "in": "body", "r": True},
            {"n": "serverUrl", "t": "string", "in": "body", "r": True},
            {"n": "topic", "t": "string", "in": "body", "r": True},
            {"n": "accessToken", "t": "string", "in": "body", "r": True},
            {"n": "priority", "t": "number", "in": "body", "r": True},
        ],
    },
    {
        "tag": "notification",
        "m": "POST",
        "p": "/notification.createPushover",
        "params": [
            {"n": "appBuildError", "t": "boolean", "in": "body"},
            {"n": "databaseBackup", "t": "boolean", "in": "body"},
            {"n": "dokployBackup", "t": "boolean", "in": "body"},
            {"n": "volumeBackup", "t": "boolean", "in": "body"},
            {"n": "dokployRestart", "t": "boolean", "in": "body"},
            {"n": "name", "t": "string", "in": "body", "r": True},
            {"n": "appDeploy", "t": "boolean", "in": "body"},
            {"n": "dockerCleanup", "t": "boolean", "in": "body"},
            {"n": "serverThreshold", "t": "boolean", "in": "body"},
            {"n": "userKey", "t": "string", "in": "body", "r": True},
            {"n": "apiToken", "t": "string", "in": "body", "r": True},
            {"n": "priority", "t": "number", "in": "body"},
            {"n": "retry", "t": "number", "in": "body"},
            {"n": "expire", "t": "number", "in": "body"},
        ],
    },
    {
        "tag": "notification",
        "m": "POST",
        "p": "/notification.createResend",
        "params": [
            {"n": "appBuildError", "t": "boolean", "in": "body", "r": True},
            {"n": "databaseBackup", "t": "boolean", "in": "body", "r": True},
            {"n": "dokployBackup", "t": "boolean", "in": "body", "r": True},
            {"n": "volumeBackup", "t": "boolean", "in": "body", "r": True},
            {"n": "dokployRestart", "t": "boolean", "in": "body", "r": True},
            {"n": "name", "t": "string", "in": "body", "r": True},
            {"n": "appDeploy", "t": "boolean", "in": "body", "r": True},
            {"n": "dockerCleanup", "t": "boolean", "in": "body", "r": True},
            {"n": "serverThreshold", "t": "boolean", "in": "body", "r": True},
            {"n": "apiKey", "t": "string", "in": "body", "r": True},
            {"n": "fromAddress", "t": "string", "in": "body", "r": True},
            {"n": "toAddresses", "t": "array", "in": "body", "r": True},
        ],
    },
    {
        "tag": "notification",
        "m": "POST",
        "p": "/notification.createSlack",
        "params": [
            {"n": "appBuildError", "t": "boolean", "in": "body", "r": True},
            {"n": "databaseBackup", "t": "boolean", "in": "body", "r": True},
            {"n": "dokployBackup", "t": "boolean", "in": "body", "r": True},
            {"n": "volumeBackup", "t": "boolean", "in": "body", "r": True},
            {"n": "dokployRestart", "t": "boolean", "in": "body", "r": True},
            {"n": "name", "t": "string", "in": "body", "r": True},
            {"n": "appDeploy", "t": "boolean", "in": "body", "r": True},
            {"n": "dockerCleanup", "t": "boolean", "in": "body", "r": True},
            {"n": "serverThreshold", "t": "boolean", "in": "body", "r": True},
            {"n": "webhookUrl", "t": "string", "in": "body", "r": True},
            {"n": "channel", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "notification",
        "m": "POST",
        "p": "/notification.createTeams",
        "params": [
            {"n": "appBuildError", "t": "boolean", "in": "body", "r": True},
            {"n": "databaseBackup", "t": "boolean", "in": "body", "r": True},
            {"n": "dokployBackup", "t": "boolean", "in": "body", "r": True},
            {"n": "volumeBackup", "t": "boolean", "in": "body", "r": True},
            {"n": "dokployRestart", "t": "boolean", "in": "body", "r": True},
            {"n": "name", "t": "string", "in": "body", "r": True},
            {"n": "appDeploy", "t": "boolean", "in": "body", "r": True},
            {"n": "dockerCleanup", "t": "boolean", "in": "body", "r": True},
            {"n": "serverThreshold", "t": "boolean", "in": "body", "r": True},
            {"n": "webhookUrl", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "notification",
        "m": "POST",
        "p": "/notification.createTelegram",
        "params": [
            {"n": "appBuildError", "t": "boolean", "in": "body", "r": True},
            {"n": "databaseBackup", "t": "boolean", "in": "body", "r": True},
            {"n": "dokployBackup", "t": "boolean", "in": "body", "r": True},
            {"n": "volumeBackup", "t": "boolean", "in": "body", "r": True},
            {"n": "dokployRestart", "t": "boolean", "in": "body", "r": True},
            {"n": "name", "t": "string", "in": "body", "r": True},
            {"n": "appDeploy", "t": "boolean", "in": "body", "r": True},
            {"n": "dockerCleanup", "t": "boolean", "in": "body", "r": True},
            {"n": "serverThreshold", "t": "boolean", "in": "body", "r": True},
            {"n": "botToken", "t": "string", "in": "body", "r": True},
            {"n": "chatId", "t": "string", "in": "body", "r": True},
            {"n": "messageThreadId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "notification",
        "m": "GET",
        "p": "/notification.getEmailProviders",
        "params": [],
    },
    {
        "tag": "notification",
        "m": "GET",
        "p": "/notification.one",
        "params": [
            {"n": "notificationId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "notification",
        "m": "POST",
        "p": "/notification.receiveNotification",
        "params": [
            {"n": "ServerType", "t": "string", "in": "body", "e": ["Dokploy", "Remote"]},
            {"n": "Type", "t": "string", "in": "body", "r": True, "e": ["Memory", "CPU"]},
            {"n": "Value", "t": "number", "in": "body", "r": True},
            {"n": "Threshold", "t": "number", "in": "body", "r": True},
            {"n": "Message", "t": "string", "in": "body", "r": True},
            {"n": "Timestamp", "t": "string", "in": "body", "r": True},
            {"n": "Token", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "notification",
        "m": "POST",
        "p": "/notification.remove",
        "params": [
            {"n": "notificationId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "notification",
        "m": "POST",
        "p": "/notification.testCustomConnection",
        "params": [
            {"n": "endpoint", "t": "string", "in": "body", "r": True},
            {"n": "headers", "t": "object", "in": "body"},
        ],
    },
    {
        "tag": "notification",
        "m": "POST",
        "p": "/notification.testDiscordConnection",
        "params": [
            {"n": "webhookUrl", "t": "string", "in": "body", "r": True},
            {"n": "decoration", "t": "boolean", "in": "body"},
        ],
    },
    {
        "tag": "notification",
        "m": "POST",
        "p": "/notification.testEmailConnection",
        "params": [
            {"n": "smtpServer", "t": "string", "in": "body", "r": True},
            {"n": "smtpPort", "t": "number", "in": "body", "r": True},
            {"n": "username", "t": "string", "in": "body", "r": True},
            {"n": "password", "t": "string", "in": "body", "r": True},
            {"n": "toAddresses", "t": "array", "in": "body", "r": True},
            {"n": "fromAddress", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "notification",
        "m": "POST",
        "p": "/notification.testGotifyConnection",
        "params": [
            {"n": "serverUrl", "t": "string", "in": "body", "r": True},
            {"n": "appToken", "t": "string", "in": "body", "r": True},
            {"n": "priority", "t": "number", "in": "body", "r": True},
            {"n": "decoration", "t": "boolean", "in": "body"},
        ],
    },
    {
        "tag": "notification",
        "m": "POST",
        "p": "/notification.testLarkConnection",
        "params": [
            {"n": "webhookUrl", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "notification",
        "m": "POST",
        "p": "/notification.testMattermostConnection",
        "params": [
            {"n": "webhookUrl", "t": "string", "in": "body", "r": True},
            {"n": "channel", "t": "string", "in": "body"},
            {"n": "username", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "notification",
        "m": "POST",
        "p": "/notification.testNtfyConnection",
        "params": [
            {"n": "serverUrl", "t": "string", "in": "body", "r": True},
            {"n": "topic", "t": "string", "in": "body", "r": True},
            {"n": "accessToken", "t": "string", "in": "body", "r": True},
            {"n": "priority", "t": "number", "in": "body", "r": True},
        ],
    },
    {
        "tag": "notification",
        "m": "POST",
        "p": "/notification.testPushoverConnection",
        "params": [
            {"n": "userKey", "t": "string", "in": "body", "r": True},
            {"n": "apiToken", "t": "string", "in": "body", "r": True},
            {"n": "priority", "t": "number", "in": "body", "r": True},
            {"n": "retry", "t": "number", "in": "body"},
            {"n": "expire", "t": "number", "in": "body"},
        ],
    },
    {
        "tag": "notification",
        "m": "POST",
        "p": "/notification.testResendConnection",
        "params": [
            {"n": "apiKey", "t": "string", "in": "body", "r": True},
            {"n": "fromAddress", "t": "string", "in": "body", "r": True},
            {"n": "toAddresses", "t": "array", "in": "body", "r": True},
        ],
    },
    {
        "tag": "notification",
        "m": "POST",
        "p": "/notification.testSlackConnection",
        "params": [
            {"n": "webhookUrl", "t": "string", "in": "body", "r": True},
            {"n": "channel", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "notification",
        "m": "POST",
        "p": "/notification.testTeamsConnection",
        "params": [
            {"n": "webhookUrl", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "notification",
        "m": "POST",
        "p": "/notification.testTelegramConnection",
        "params": [
            {"n": "botToken", "t": "string", "in": "body", "r": True},
            {"n": "chatId", "t": "string", "in": "body", "r": True},
            {"n": "messageThreadId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "notification",
        "m": "POST",
        "p": "/notification.updateCustom",
        "params": [
            {"n": "appBuildError", "t": "boolean", "in": "body"},
            {"n": "databaseBackup", "t": "boolean", "in": "body"},
            {"n": "dokployBackup", "t": "boolean", "in": "body"},
            {"n": "volumeBackup", "t": "boolean", "in": "body"},
            {"n": "dokployRestart", "t": "boolean", "in": "body"},
            {"n": "name", "t": "string", "in": "body"},
            {"n": "appDeploy", "t": "boolean", "in": "body"},
            {"n": "dockerCleanup", "t": "boolean", "in": "body"},
            {"n": "serverThreshold", "t": "boolean", "in": "body"},
            {"n": "endpoint", "t": "string", "in": "body"},
            {"n": "headers", "t": "object", "in": "body"},
            {"n": "notificationId", "t": "string", "in": "body", "r": True},
            {"n": "customId", "t": "string", "in": "body", "r": True},
            {"n": "organizationId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "notification",
        "m": "POST",
        "p": "/notification.updateDiscord",
        "params": [
            {"n": "appBuildError", "t": "boolean", "in": "body"},
            {"n": "databaseBackup", "t": "boolean", "in": "body"},
            {"n": "dokployBackup", "t": "boolean", "in": "body"},
            {"n": "volumeBackup", "t": "boolean", "in": "body"},
            {"n": "dokployRestart", "t": "boolean", "in": "body"},
            {"n": "name", "t": "string", "in": "body"},
            {"n": "appDeploy", "t": "boolean", "in": "body"},
            {"n": "dockerCleanup", "t": "boolean", "in": "body"},
            {"n": "serverThreshold", "t": "boolean", "in": "body"},
            {"n": "webhookUrl", "t": "string", "in": "body"},
            {"n": "decoration", "t": "boolean", "in": "body"},
            {"n": "notificationId", "t": "string", "in": "body", "r": True},
            {"n": "discordId", "t": "string", "in": "body", "r": True},
            {"n": "organizationId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "notification",
        "m": "POST",
        "p": "/notification.updateEmail",
        "params": [
            {"n": "appBuildError", "t": "boolean", "in": "body"},
            {"n": "databaseBackup", "t": "boolean", "in": "body"},
            {"n": "dokployBackup", "t": "boolean", "in": "body"},
            {"n": "volumeBackup", "t": "boolean", "in": "body"},
            {"n": "dokployRestart", "t": "boolean", "in": "body"},
            {"n": "name", "t": "string", "in": "body"},
            {"n": "appDeploy", "t": "boolean", "in": "body"},
            {"n": "dockerCleanup", "t": "boolean", "in": "body"},
            {"n": "serverThreshold", "t": "boolean", "in": "body"},
            {"n": "smtpServer", "t": "string", "in": "body"},
            {"n": "smtpPort", "t": "number", "in": "body"},
            {"n": "username", "t": "string", "in": "body"},
            {"n": "password", "t": "string", "in": "body"},
            {"n": "fromAddress", "t": "string", "in": "body"},
            {"n": "toAddresses", "t": "array", "in": "body"},
            {"n": "notificationId", "t": "string", "in": "body", "r": True},
            {"n": "emailId", "t": "string", "in": "body", "r": True},
            {"n": "organizationId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "notification",
        "m": "POST",
        "p": "/notification.updateGotify",
        "params": [
            {"n": "appBuildError", "t": "boolean", "in": "body"},
            {"n": "databaseBackup", "t": "boolean", "in": "body"},
            {"n": "dokployBackup", "t": "boolean", "in": "body"},
            {"n": "volumeBackup", "t": "boolean", "in": "body"},
            {"n": "dokployRestart", "t": "boolean", "in": "body"},
            {"n": "name", "t": "string", "in": "body"},
            {"n": "appDeploy", "t": "boolean", "in": "body"},
            {"n": "dockerCleanup", "t": "boolean", "in": "body"},
            {"n": "serverUrl", "t": "string", "in": "body"},
            {"n": "appToken", "t": "string", "in": "body"},
            {"n": "priority", "t": "number", "in": "body"},
            {"n": "decoration", "t": "boolean", "in": "body"},
            {"n": "notificationId", "t": "string", "in": "body", "r": True},
            {"n": "gotifyId", "t": "string", "in": "body", "r": True},
            {"n": "organizationId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "notification",
        "m": "POST",
        "p": "/notification.updateLark",
        "params": [
            {"n": "appBuildError", "t": "boolean", "in": "body"},
            {"n": "databaseBackup", "t": "boolean", "in": "body"},
            {"n": "dokployBackup", "t": "boolean", "in": "body"},
            {"n": "volumeBackup", "t": "boolean", "in": "body"},
            {"n": "dokployRestart", "t": "boolean", "in": "body"},
            {"n": "name", "t": "string", "in": "body"},
            {"n": "appDeploy", "t": "boolean", "in": "body"},
            {"n": "dockerCleanup", "t": "boolean", "in": "body"},
            {"n": "serverThreshold", "t": "boolean", "in": "body"},
            {"n": "webhookUrl", "t": "string", "in": "body"},
            {"n": "notificationId", "t": "string", "in": "body", "r": True},
            {"n": "larkId", "t": "string", "in": "body", "r": True},
            {"n": "organizationId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "notification",
        "m": "POST",
        "p": "/notification.updateMattermost",
        "params": [
            {"n": "appBuildError", "t": "boolean", "in": "body"},
            {"n": "databaseBackup", "t": "boolean", "in": "body"},
            {"n": "dokployBackup", "t": "boolean", "in": "body"},
            {"n": "volumeBackup", "t": "boolean", "in": "body"},
            {"n": "dokployRestart", "t": "boolean", "in": "body"},
            {"n": "name", "t": "string", "in": "body"},
            {"n": "appDeploy", "t": "boolean", "in": "body"},
            {"n": "dockerCleanup", "t": "boolean", "in": "body"},
            {"n": "serverThreshold", "t": "boolean", "in": "body"},
            {"n": "webhookUrl", "t": "string", "in": "body"},
            {"n": "channel", "t": "string", "in": "body"},
            {"n": "username", "t": "string", "in": "body"},
            {"n": "notificationId", "t": "string", "in": "body", "r": True},
            {"n": "mattermostId", "t": "string", "in": "body", "r": True},
            {"n": "organizationId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "notification",
        "m": "POST",
        "p": "/notification.updateNtfy",
        "params": [
            {"n": "appBuildError", "t": "boolean", "in": "body"},
            {"n": "databaseBackup", "t": "boolean", "in": "body"},
            {"n": "dokployBackup", "t": "boolean", "in": "body"},
            {"n": "volumeBackup", "t": "boolean", "in": "body"},
            {"n": "dokployRestart", "t": "boolean", "in": "body"},
            {"n": "name", "t": "string", "in": "body"},
            {"n": "appDeploy", "t": "boolean", "in": "body"},
            {"n": "dockerCleanup", "t": "boolean", "in": "body"},
            {"n": "serverUrl", "t": "string", "in": "body"},
            {"n": "topic", "t": "string", "in": "body"},
            {"n": "accessToken", "t": "string", "in": "body"},
            {"n": "priority", "t": "number", "in": "body"},
            {"n": "notificationId", "t": "string", "in": "body", "r": True},
            {"n": "ntfyId", "t": "string", "in": "body", "r": True},
            {"n": "organizationId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "notification",
        "m": "POST",
        "p": "/notification.updatePushover",
        "params": [
            {"n": "notificationId", "t": "string", "in": "body", "r": True},
            {"n": "pushoverId", "t": "string", "in": "body", "r": True},
            {"n": "organizationId", "t": "string", "in": "body"},
            {"n": "userKey", "t": "string", "in": "body"},
            {"n": "apiToken", "t": "string", "in": "body"},
            {"n": "priority", "t": "number", "in": "body"},
            {"n": "retry", "t": "number", "in": "body"},
            {"n": "expire", "t": "number", "in": "body"},
            {"n": "appBuildError", "t": "boolean", "in": "body"},
            {"n": "databaseBackup", "t": "boolean", "in": "body"},
            {"n": "dokployBackup", "t": "boolean", "in": "body"},
            {"n": "volumeBackup", "t": "boolean", "in": "body"},
            {"n": "dokployRestart", "t": "boolean", "in": "body"},
            {"n": "name", "t": "string", "in": "body"},
            {"n": "appDeploy", "t": "boolean", "in": "body"},
            {"n": "dockerCleanup", "t": "boolean", "in": "body"},
            {"n": "serverThreshold", "t": "boolean", "in": "body"},
        ],
    },
    {
        "tag": "notification",
        "m": "POST",
        "p": "/notification.updateResend",
        "params": [
            {"n": "appBuildError", "t": "boolean", "in": "body"},
            {"n": "databaseBackup", "t": "boolean", "in": "body"},
            {"n": "dokployBackup", "t": "boolean", "in": "body"},
            {"n": "volumeBackup", "t": "boolean", "in": "body"},
            {"n": "dokployRestart", "t": "boolean", "in": "body"},
            {"n": "name", "t": "string", "in": "body"},
            {"n": "appDeploy", "t": "boolean", "in": "body"},
            {"n": "dockerCleanup", "t": "boolean", "in": "body"},
            {"n": "serverThreshold", "t": "boolean", "in": "body"},
            {"n": "apiKey", "t": "string", "in": "body"},
            {"n": "fromAddress", "t": "string", "in": "body"},
            {"n": "toAddresses", "t": "array", "in": "body"},
            {"n": "notificationId", "t": "string", "in": "body", "r": True},
            {"n": "resendId", "t": "string", "in": "body", "r": True},
            {"n": "organizationId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "notification",
        "m": "POST",
        "p": "/notification.updateSlack",
        "params": [
            {"n": "appBuildError", "t": "boolean", "in": "body"},
            {"n": "databaseBackup", "t": "boolean", "in": "body"},
            {"n": "dokployBackup", "t": "boolean", "in": "body"},
            {"n": "volumeBackup", "t": "boolean", "in": "body"},
            {"n": "dokployRestart", "t": "boolean", "in": "body"},
            {"n": "name", "t": "string", "in": "body"},
            {"n": "appDeploy", "t": "boolean", "in": "body"},
            {"n": "dockerCleanup", "t": "boolean", "in": "body"},
            {"n": "serverThreshold", "t": "boolean", "in": "body"},
            {"n": "webhookUrl", "t": "string", "in": "body"},
            {"n": "channel", "t": "string", "in": "body"},
            {"n": "notificationId", "t": "string", "in": "body", "r": True},
            {"n": "slackId", "t": "string", "in": "body", "r": True},
            {"n": "organizationId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "notification",
        "m": "POST",
        "p": "/notification.updateTeams",
        "params": [
            {"n": "appBuildError", "t": "boolean", "in": "body"},
            {"n": "databaseBackup", "t": "boolean", "in": "body"},
            {"n": "dokployBackup", "t": "boolean", "in": "body"},
            {"n": "volumeBackup", "t": "boolean", "in": "body"},
            {"n": "dokployRestart", "t": "boolean", "in": "body"},
            {"n": "name", "t": "string", "in": "body"},
            {"n": "appDeploy", "t": "boolean", "in": "body"},
            {"n": "dockerCleanup", "t": "boolean", "in": "body"},
            {"n": "serverThreshold", "t": "boolean", "in": "body"},
            {"n": "webhookUrl", "t": "string", "in": "body"},
            {"n": "notificationId", "t": "string", "in": "body", "r": True},
            {"n": "teamsId", "t": "string", "in": "body", "r": True},
            {"n": "organizationId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "notification",
        "m": "POST",
        "p": "/notification.updateTelegram",
        "params": [
            {"n": "appBuildError", "t": "boolean", "in": "body"},
            {"n": "databaseBackup", "t": "boolean", "in": "body"},
            {"n": "dokployBackup", "t": "boolean", "in": "body"},
            {"n": "volumeBackup", "t": "boolean", "in": "body"},
            {"n": "dokployRestart", "t": "boolean", "in": "body"},
            {"n": "name", "t": "string", "in": "body"},
            {"n": "appDeploy", "t": "boolean", "in": "body"},
            {"n": "dockerCleanup", "t": "boolean", "in": "body"},
            {"n": "serverThreshold", "t": "boolean", "in": "body"},
            {"n": "botToken", "t": "string", "in": "body"},
            {"n": "chatId", "t": "string", "in": "body"},
            {"n": "messageThreadId", "t": "string", "in": "body"},
            {"n": "notificationId", "t": "string", "in": "body", "r": True},
            {"n": "telegramId", "t": "string", "in": "body", "r": True},
            {"n": "organizationId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "organization",
        "m": "GET",
        "p": "/organization.active",
        "params": [],
    },
    {
        "tag": "organization",
        "m": "GET",
        "p": "/organization.all",
        "params": [],
    },
    {
        "tag": "organization",
        "m": "GET",
        "p": "/organization.allInvitations",
        "params": [],
    },
    {
        "tag": "organization",
        "m": "POST",
        "p": "/organization.create",
        "params": [
            {"n": "name", "t": "string", "in": "body", "r": True},
            {"n": "logo", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "organization",
        "m": "POST",
        "p": "/organization.delete",
        "params": [
            {"n": "organizationId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "organization",
        "m": "POST",
        "p": "/organization.inviteMember",
        "params": [
            {"n": "email", "t": "string", "in": "body", "r": True},
            {"n": "role", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "organization",
        "m": "GET",
        "p": "/organization.one",
        "params": [
            {"n": "organizationId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "organization",
        "m": "POST",
        "p": "/organization.removeInvitation",
        "params": [
            {"n": "invitationId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "organization",
        "m": "POST",
        "p": "/organization.setDefault",
        "params": [
            {"n": "organizationId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "organization",
        "m": "POST",
        "p": "/organization.update",
        "params": [
            {"n": "organizationId", "t": "string", "in": "body", "r": True},
            {"n": "name", "t": "string", "in": "body", "r": True},
            {"n": "logo", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "organization",
        "m": "POST",
        "p": "/organization.updateMemberRole",
        "params": [
            {"n": "memberId", "t": "string", "in": "body", "r": True},
            {"n": "role", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "patch",
        "m": "GET",
        "p": "/patch.byEntityId",
        "params": [
            {"n": "id", "t": "string", "in": "query", "r": True},
            {"n": "type", "t": "string", "in": "query", "r": True, "e": ["application", "compose"]},
        ],
    },
    {
        "tag": "patch",
        "m": "POST",
        "p": "/patch.cleanPatchRepos",
        "params": [
            {"n": "serverId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "patch",
        "m": "POST",
        "p": "/patch.create",
        "params": [
            {"n": "filePath", "t": "string", "in": "body", "r": True},
            {"n": "content", "t": "string", "in": "body", "r": True},
            {"n": "type", "t": "string", "in": "body", "e": ["create", "update", "delete"]},
            {"n": "enabled", "t": "boolean", "in": "body"},
            {"n": "applicationId", "t": "string", "in": "body"},
            {"n": "composeId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "patch",
        "m": "POST",
        "p": "/patch.delete",
        "params": [
            {"n": "patchId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "patch",
        "m": "POST",
        "p": "/patch.ensureRepo",
        "params": [
            {"n": "id", "t": "string", "in": "body", "r": True},
            {"n": "type", "t": "string", "in": "body", "r": True, "e": ["application", "compose"]},
        ],
    },
    {
        "tag": "patch",
        "m": "POST",
        "p": "/patch.markFileForDeletion",
        "params": [
            {"n": "id", "t": "string", "in": "body", "r": True},
            {"n": "type", "t": "string", "in": "body", "r": True, "e": ["application", "compose"]},
            {"n": "filePath", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "patch",
        "m": "GET",
        "p": "/patch.one",
        "params": [
            {"n": "patchId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "patch",
        "m": "GET",
        "p": "/patch.readRepoDirectories",
        "params": [
            {"n": "id", "t": "string", "in": "query", "r": True},
            {"n": "type", "t": "string", "in": "query", "r": True, "e": ["application", "compose"]},
            {"n": "repoPath", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "patch",
        "m": "GET",
        "p": "/patch.readRepoFile",
        "params": [
            {"n": "id", "t": "string", "in": "query", "r": True},
            {"n": "type", "t": "string", "in": "query", "r": True, "e": ["application", "compose"]},
            {"n": "filePath", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "patch",
        "m": "POST",
        "p": "/patch.saveFileAsPatch",
        "params": [
            {"n": "id", "t": "string", "in": "body", "r": True},
            {"n": "type", "t": "string", "in": "body", "r": True, "e": ["application", "compose"]},
            {"n": "filePath", "t": "string", "in": "body", "r": True},
            {"n": "content", "t": "string", "in": "body", "r": True},
            {"n": "patchType", "t": "string", "in": "body", "e": ["create", "update"]},
        ],
    },
    {
        "tag": "patch",
        "m": "POST",
        "p": "/patch.toggleEnabled",
        "params": [
            {"n": "patchId", "t": "string", "in": "body", "r": True},
            {"n": "enabled", "t": "boolean", "in": "body", "r": True},
        ],
    },
    {
        "tag": "patch",
        "m": "POST",
        "p": "/patch.update",
        "params": [
            {"n": "patchId", "t": "string", "in": "body", "r": True},
            {"n": "type", "t": "string", "in": "body", "e": ["create", "update", "delete"]},
            {"n": "filePath", "t": "string", "in": "body"},
            {"n": "enabled", "t": "boolean", "in": "body"},
            {"n": "content", "t": "string", "in": "body"},
            {"n": "createdAt", "t": "string", "in": "body"},
            {"n": "updatedAt", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "port",
        "m": "POST",
        "p": "/port.create",
        "params": [
            {"n": "publishedPort", "t": "number", "in": "body", "r": True},
            {"n": "publishMode", "t": "string", "in": "body", "r": True, "e": ["ingress", "host"]},
            {"n": "targetPort", "t": "number", "in": "body", "r": True},
            {"n": "protocol", "t": "string", "in": "body", "r": True, "e": ["tcp", "udp"]},
            {"n": "applicationId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "port",
        "m": "POST",
        "p": "/port.delete",
        "params": [
            {"n": "portId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "port",
        "m": "GET",
        "p": "/port.one",
        "params": [
            {"n": "portId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "port",
        "m": "POST",
        "p": "/port.update",
        "params": [
            {"n": "portId", "t": "string", "in": "body", "r": True},
            {"n": "publishedPort", "t": "number", "in": "body", "r": True},
            {"n": "publishMode", "t": "string", "in": "body", "r": True, "e": ["ingress", "host"]},
            {"n": "targetPort", "t": "number", "in": "body", "r": True},
            {"n": "protocol", "t": "string", "in": "body", "r": True, "e": ["tcp", "udp"]},
        ],
    },
    {
        "tag": "postgres",
        "m": "POST",
        "p": "/postgres.changePassword",
        "params": [
            {"n": "postgresId", "t": "string", "in": "body", "r": True},
            {"n": "password", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "postgres",
        "m": "POST",
        "p": "/postgres.changeStatus",
        "params": [
            {"n": "postgresId", "t": "string", "in": "body", "r": True},
            {"n": "applicationStatus", "t": "string", "in": "body", "r": True, "e": ["idle", "running", "done", "error"]},
        ],
    },
    {
        "tag": "postgres",
        "m": "POST",
        "p": "/postgres.create",
        "params": [
            {"n": "name", "t": "string", "in": "body", "r": True},
            {"n": "appName", "t": "string", "in": "body"},
            {"n": "databaseName", "t": "string", "in": "body", "r": True},
            {"n": "databaseUser", "t": "string", "in": "body", "r": True},
            {"n": "databasePassword", "t": "string", "in": "body", "r": True},
            {"n": "dockerImage", "t": "string", "in": "body"},
            {"n": "environmentId", "t": "string", "in": "body", "r": True},
            {"n": "description", "t": "string", "in": "body"},
            {"n": "serverId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "postgres",
        "m": "POST",
        "p": "/postgres.deploy",
        "params": [
            {"n": "postgresId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "postgres",
        "m": "POST",
        "p": "/postgres.move",
        "params": [
            {"n": "postgresId", "t": "string", "in": "body", "r": True},
            {"n": "targetEnvironmentId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "postgres",
        "m": "GET",
        "p": "/postgres.one",
        "params": [
            {"n": "postgresId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "postgres",
        "m": "GET",
        "p": "/postgres.readLogs",
        "params": [
            {"n": "postgresId", "t": "string", "in": "query", "r": True},
            {"n": "tail", "t": "integer", "in": "query"},
            {"n": "since", "t": "string", "in": "query"},
            {"n": "search", "t": "string", "in": "query"},
        ],
    },
    {
        "tag": "postgres",
        "m": "POST",
        "p": "/postgres.rebuild",
        "params": [
            {"n": "postgresId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "postgres",
        "m": "POST",
        "p": "/postgres.reload",
        "params": [
            {"n": "postgresId", "t": "string", "in": "body", "r": True},
            {"n": "appName", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "postgres",
        "m": "POST",
        "p": "/postgres.remove",
        "params": [
            {"n": "postgresId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "postgres",
        "m": "POST",
        "p": "/postgres.saveEnvironment",
        "params": [
            {"n": "postgresId", "t": "string", "in": "body", "r": True},
            {"n": "env", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "postgres",
        "m": "POST",
        "p": "/postgres.saveExternalPort",
        "params": [
            {"n": "postgresId", "t": "string", "in": "body", "r": True},
            {"n": "externalPort", "t": "number", "in": "body", "r": True},
        ],
    },
    {
        "tag": "postgres",
        "m": "GET",
        "p": "/postgres.search",
        "params": [
            {"n": "q", "t": "string", "in": "query"},
            {"n": "name", "t": "string", "in": "query"},
            {"n": "appName", "t": "string", "in": "query"},
            {"n": "description", "t": "string", "in": "query"},
            {"n": "projectId", "t": "string", "in": "query"},
            {"n": "environmentId", "t": "string", "in": "query"},
            {"n": "limit", "t": "number", "in": "query"},
            {"n": "offset", "t": "number", "in": "query"},
        ],
    },
    {
        "tag": "postgres",
        "m": "POST",
        "p": "/postgres.start",
        "params": [
            {"n": "postgresId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "postgres",
        "m": "POST",
        "p": "/postgres.stop",
        "params": [
            {"n": "postgresId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "postgres",
        "m": "POST",
        "p": "/postgres.update",
        "params": [
            {"n": "postgresId", "t": "string", "in": "body", "r": True},
            {"n": "name", "t": "string", "in": "body"},
            {"n": "appName", "t": "string", "in": "body"},
            {"n": "databaseName", "t": "string", "in": "body"},
            {"n": "databaseUser", "t": "string", "in": "body"},
            {"n": "databasePassword", "t": "string", "in": "body"},
            {"n": "description", "t": "string", "in": "body"},
            {"n": "dockerImage", "t": "string", "in": "body"},
            {"n": "command", "t": "string", "in": "body"},
            {"n": "args", "t": "array", "in": "body"},
            {"n": "env", "t": "string", "in": "body"},
            {"n": "memoryReservation", "t": "string", "in": "body"},
            {"n": "externalPort", "t": "number", "in": "body"},
            {"n": "memoryLimit", "t": "string", "in": "body"},
            {"n": "cpuReservation", "t": "string", "in": "body"},
            {"n": "cpuLimit", "t": "string", "in": "body"},
            {"n": "applicationStatus", "t": "string", "in": "body", "e": ["idle", "running", "done", "error"]},
            {"n": "healthCheckSwarm", "t": "object", "in": "body"},
            {"n": "restartPolicySwarm", "t": "object", "in": "body"},
            {"n": "placementSwarm", "t": "object", "in": "body"},
            {"n": "updateConfigSwarm", "t": "object", "in": "body"},
            {"n": "rollbackConfigSwarm", "t": "object", "in": "body"},
            {"n": "modeSwarm", "t": "object", "in": "body"},
            {"n": "labelsSwarm", "t": "object", "in": "body"},
            {"n": "networkSwarm", "t": "array", "in": "body"},
            {"n": "stopGracePeriodSwarm", "t": "number", "in": "body"},
            {"n": "endpointSpecSwarm", "t": "object", "in": "body"},
            {"n": "ulimitsSwarm", "t": "array", "in": "body"},
            {"n": "replicas", "t": "number", "in": "body"},
            {"n": "createdAt", "t": "string", "in": "body"},
            {"n": "environmentId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "previewDeployment",
        "m": "GET",
        "p": "/previewDeployment.all",
        "params": [
            {"n": "applicationId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "previewDeployment",
        "m": "POST",
        "p": "/previewDeployment.delete",
        "params": [
            {"n": "previewDeploymentId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "previewDeployment",
        "m": "GET",
        "p": "/previewDeployment.one",
        "params": [
            {"n": "previewDeploymentId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "previewDeployment",
        "m": "POST",
        "p": "/previewDeployment.redeploy",
        "params": [
            {"n": "previewDeploymentId", "t": "string", "in": "body", "r": True},
            {"n": "title", "t": "string", "in": "body"},
            {"n": "description", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "project",
        "m": "GET",
        "p": "/project.all",
        "params": [],
    },
    {
        "tag": "project",
        "m": "GET",
        "p": "/project.allForPermissions",
        "params": [],
    },
    {
        "tag": "project",
        "m": "POST",
        "p": "/project.create",
        "params": [
            {"n": "name", "t": "string", "in": "body", "r": True},
            {"n": "description", "t": "string", "in": "body"},
            {"n": "env", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "project",
        "m": "POST",
        "p": "/project.duplicate",
        "params": [
            {"n": "sourceEnvironmentId", "t": "string", "in": "body", "r": True},
            {"n": "name", "t": "string", "in": "body", "r": True},
            {"n": "description", "t": "string", "in": "body"},
            {"n": "includeServices", "t": "boolean", "in": "body"},
            {"n": "selectedServices", "t": "array", "in": "body"},
            {"n": "duplicateInSameProject", "t": "boolean", "in": "body"},
        ],
    },
    {
        "tag": "project",
        "m": "GET",
        "p": "/project.homeStats",
        "params": [],
    },
    {
        "tag": "project",
        "m": "GET",
        "p": "/project.one",
        "params": [
            {"n": "projectId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "project",
        "m": "POST",
        "p": "/project.remove",
        "params": [
            {"n": "projectId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "project",
        "m": "GET",
        "p": "/project.search",
        "params": [
            {"n": "q", "t": "string", "in": "query"},
            {"n": "name", "t": "string", "in": "query"},
            {"n": "description", "t": "string", "in": "query"},
            {"n": "limit", "t": "number", "in": "query"},
            {"n": "offset", "t": "number", "in": "query"},
        ],
    },
    {
        "tag": "project",
        "m": "POST",
        "p": "/project.update",
        "params": [
            {"n": "projectId", "t": "string", "in": "body", "r": True},
            {"n": "name", "t": "string", "in": "body"},
            {"n": "description", "t": "string", "in": "body"},
            {"n": "createdAt", "t": "string", "in": "body"},
            {"n": "organizationId", "t": "string", "in": "body"},
            {"n": "env", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "redirects",
        "m": "POST",
        "p": "/redirects.create",
        "params": [
            {"n": "regex", "t": "string", "in": "body", "r": True},
            {"n": "replacement", "t": "string", "in": "body", "r": True},
            {"n": "permanent", "t": "boolean", "in": "body", "r": True},
            {"n": "applicationId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "redirects",
        "m": "POST",
        "p": "/redirects.delete",
        "params": [
            {"n": "redirectId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "redirects",
        "m": "GET",
        "p": "/redirects.one",
        "params": [
            {"n": "redirectId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "redirects",
        "m": "POST",
        "p": "/redirects.update",
        "params": [
            {"n": "redirectId", "t": "string", "in": "body", "r": True},
            {"n": "regex", "t": "string", "in": "body", "r": True},
            {"n": "replacement", "t": "string", "in": "body", "r": True},
            {"n": "permanent", "t": "boolean", "in": "body", "r": True},
        ],
    },
    {
        "tag": "redis",
        "m": "POST",
        "p": "/redis.changePassword",
        "params": [
            {"n": "redisId", "t": "string", "in": "body", "r": True},
            {"n": "password", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "redis",
        "m": "POST",
        "p": "/redis.changeStatus",
        "params": [
            {"n": "redisId", "t": "string", "in": "body", "r": True},
            {"n": "applicationStatus", "t": "string", "in": "body", "r": True, "e": ["idle", "running", "done", "error"]},
        ],
    },
    {
        "tag": "redis",
        "m": "POST",
        "p": "/redis.create",
        "params": [
            {"n": "name", "t": "string", "in": "body", "r": True},
            {"n": "appName", "t": "string", "in": "body"},
            {"n": "databasePassword", "t": "string", "in": "body", "r": True},
            {"n": "dockerImage", "t": "string", "in": "body"},
            {"n": "environmentId", "t": "string", "in": "body", "r": True},
            {"n": "description", "t": "string", "in": "body"},
            {"n": "serverId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "redis",
        "m": "POST",
        "p": "/redis.deploy",
        "params": [
            {"n": "redisId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "redis",
        "m": "POST",
        "p": "/redis.move",
        "params": [
            {"n": "redisId", "t": "string", "in": "body", "r": True},
            {"n": "targetEnvironmentId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "redis",
        "m": "GET",
        "p": "/redis.one",
        "params": [
            {"n": "redisId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "redis",
        "m": "GET",
        "p": "/redis.readLogs",
        "params": [
            {"n": "redisId", "t": "string", "in": "query", "r": True},
            {"n": "tail", "t": "integer", "in": "query"},
            {"n": "since", "t": "string", "in": "query"},
            {"n": "search", "t": "string", "in": "query"},
        ],
    },
    {
        "tag": "redis",
        "m": "POST",
        "p": "/redis.rebuild",
        "params": [
            {"n": "redisId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "redis",
        "m": "POST",
        "p": "/redis.reload",
        "params": [
            {"n": "redisId", "t": "string", "in": "body", "r": True},
            {"n": "appName", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "redis",
        "m": "POST",
        "p": "/redis.remove",
        "params": [
            {"n": "redisId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "redis",
        "m": "POST",
        "p": "/redis.saveEnvironment",
        "params": [
            {"n": "redisId", "t": "string", "in": "body", "r": True},
            {"n": "env", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "redis",
        "m": "POST",
        "p": "/redis.saveExternalPort",
        "params": [
            {"n": "redisId", "t": "string", "in": "body", "r": True},
            {"n": "externalPort", "t": "number", "in": "body", "r": True},
        ],
    },
    {
        "tag": "redis",
        "m": "GET",
        "p": "/redis.search",
        "params": [
            {"n": "q", "t": "string", "in": "query"},
            {"n": "name", "t": "string", "in": "query"},
            {"n": "appName", "t": "string", "in": "query"},
            {"n": "description", "t": "string", "in": "query"},
            {"n": "projectId", "t": "string", "in": "query"},
            {"n": "environmentId", "t": "string", "in": "query"},
            {"n": "limit", "t": "number", "in": "query"},
            {"n": "offset", "t": "number", "in": "query"},
        ],
    },
    {
        "tag": "redis",
        "m": "POST",
        "p": "/redis.start",
        "params": [
            {"n": "redisId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "redis",
        "m": "POST",
        "p": "/redis.stop",
        "params": [
            {"n": "redisId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "redis",
        "m": "POST",
        "p": "/redis.update",
        "params": [
            {"n": "redisId", "t": "string", "in": "body", "r": True},
            {"n": "name", "t": "string", "in": "body"},
            {"n": "appName", "t": "string", "in": "body"},
            {"n": "description", "t": "string", "in": "body"},
            {"n": "databasePassword", "t": "string", "in": "body"},
            {"n": "dockerImage", "t": "string", "in": "body"},
            {"n": "command", "t": "string", "in": "body"},
            {"n": "args", "t": "array", "in": "body"},
            {"n": "env", "t": "string", "in": "body"},
            {"n": "memoryReservation", "t": "string", "in": "body"},
            {"n": "memoryLimit", "t": "string", "in": "body"},
            {"n": "cpuReservation", "t": "string", "in": "body"},
            {"n": "cpuLimit", "t": "string", "in": "body"},
            {"n": "externalPort", "t": "number", "in": "body"},
            {"n": "createdAt", "t": "string", "in": "body"},
            {"n": "applicationStatus", "t": "string", "in": "body", "e": ["idle", "running", "done", "error"]},
            {"n": "healthCheckSwarm", "t": "object", "in": "body"},
            {"n": "restartPolicySwarm", "t": "object", "in": "body"},
            {"n": "placementSwarm", "t": "object", "in": "body"},
            {"n": "updateConfigSwarm", "t": "object", "in": "body"},
            {"n": "rollbackConfigSwarm", "t": "object", "in": "body"},
            {"n": "modeSwarm", "t": "object", "in": "body"},
            {"n": "labelsSwarm", "t": "object", "in": "body"},
            {"n": "networkSwarm", "t": "array", "in": "body"},
            {"n": "stopGracePeriodSwarm", "t": "number", "in": "body"},
            {"n": "endpointSpecSwarm", "t": "object", "in": "body"},
            {"n": "ulimitsSwarm", "t": "array", "in": "body"},
            {"n": "replicas", "t": "number", "in": "body"},
            {"n": "environmentId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "registry",
        "m": "GET",
        "p": "/registry.all",
        "params": [],
    },
    {
        "tag": "registry",
        "m": "POST",
        "p": "/registry.create",
        "params": [
            {"n": "registryName", "t": "string", "in": "body", "r": True},
            {"n": "username", "t": "string", "in": "body", "r": True},
            {"n": "password", "t": "string", "in": "body", "r": True},
            {"n": "registryUrl", "t": "string", "in": "body", "r": True},
            {"n": "registryType", "t": "string", "in": "body", "r": True, "e": ["cloud"]},
            {"n": "imagePrefix", "t": "string", "in": "body", "r": True},
            {"n": "serverId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "registry",
        "m": "GET",
        "p": "/registry.one",
        "params": [
            {"n": "registryId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "registry",
        "m": "POST",
        "p": "/registry.remove",
        "params": [
            {"n": "registryId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "registry",
        "m": "POST",
        "p": "/registry.testRegistry",
        "params": [
            {"n": "registryName", "t": "string", "in": "body"},
            {"n": "username", "t": "string", "in": "body", "r": True},
            {"n": "password", "t": "string", "in": "body", "r": True},
            {"n": "registryUrl", "t": "string", "in": "body", "r": True},
            {"n": "registryType", "t": "string", "in": "body", "r": True, "e": ["cloud"]},
            {"n": "imagePrefix", "t": "string", "in": "body"},
            {"n": "serverId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "registry",
        "m": "POST",
        "p": "/registry.testRegistryById",
        "params": [
            {"n": "registryId", "t": "string", "in": "body"},
            {"n": "serverId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "registry",
        "m": "POST",
        "p": "/registry.update",
        "params": [
            {"n": "registryId", "t": "string", "in": "body", "r": True},
            {"n": "registryName", "t": "string", "in": "body"},
            {"n": "imagePrefix", "t": "string", "in": "body"},
            {"n": "username", "t": "string", "in": "body"},
            {"n": "password", "t": "string", "in": "body"},
            {"n": "registryUrl", "t": "string", "in": "body"},
            {"n": "createdAt", "t": "string", "in": "body"},
            {"n": "registryType", "t": "string", "in": "body", "e": ["cloud"]},
            {"n": "organizationId", "t": "string", "in": "body"},
            {"n": "serverId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "rollback",
        "m": "POST",
        "p": "/rollback.delete",
        "params": [
            {"n": "rollbackId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "rollback",
        "m": "POST",
        "p": "/rollback.rollback",
        "params": [
            {"n": "rollbackId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "schedule",
        "m": "POST",
        "p": "/schedule.create",
        "params": [
            {"n": "scheduleId", "t": "string", "in": "body"},
            {"n": "name", "t": "string", "in": "body", "r": True},
            {"n": "description", "t": "string", "in": "body"},
            {"n": "cronExpression", "t": "string", "in": "body", "r": True},
            {"n": "appName", "t": "string", "in": "body"},
            {"n": "serviceName", "t": "string", "in": "body"},
            {"n": "shellType", "t": "string", "in": "body", "e": ["bash", "sh"]},
            {"n": "scheduleType", "t": "string", "in": "body", "e": ["application", "compose", "server", "dokploy-server"]},
            {"n": "command", "t": "string", "in": "body", "r": True},
            {"n": "script", "t": "string", "in": "body"},
            {"n": "applicationId", "t": "string", "in": "body"},
            {"n": "composeId", "t": "string", "in": "body"},
            {"n": "serverId", "t": "string", "in": "body"},
            {"n": "organizationId", "t": "string", "in": "body"},
            {"n": "enabled", "t": "boolean", "in": "body"},
            {"n": "timezone", "t": "string", "in": "body"},
            {"n": "createdAt", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "schedule",
        "m": "POST",
        "p": "/schedule.delete",
        "params": [
            {"n": "scheduleId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "schedule",
        "m": "GET",
        "p": "/schedule.list",
        "params": [
            {"n": "id", "t": "string", "in": "query", "r": True},
            {"n": "scheduleType", "t": "string", "in": "query", "r": True, "e": ["application", "compose", "server", "dokploy-server"]},
        ],
    },
    {
        "tag": "schedule",
        "m": "GET",
        "p": "/schedule.one",
        "params": [
            {"n": "scheduleId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "schedule",
        "m": "POST",
        "p": "/schedule.runManually",
        "params": [
            {"n": "scheduleId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "schedule",
        "m": "POST",
        "p": "/schedule.update",
        "params": [
            {"n": "scheduleId", "t": "string", "in": "body", "r": True},
            {"n": "name", "t": "string", "in": "body", "r": True},
            {"n": "description", "t": "string", "in": "body"},
            {"n": "cronExpression", "t": "string", "in": "body", "r": True},
            {"n": "appName", "t": "string", "in": "body"},
            {"n": "serviceName", "t": "string", "in": "body"},
            {"n": "shellType", "t": "string", "in": "body", "e": ["bash", "sh"]},
            {"n": "scheduleType", "t": "string", "in": "body", "e": ["application", "compose", "server", "dokploy-server"]},
            {"n": "command", "t": "string", "in": "body", "r": True},
            {"n": "script", "t": "string", "in": "body"},
            {"n": "applicationId", "t": "string", "in": "body"},
            {"n": "composeId", "t": "string", "in": "body"},
            {"n": "serverId", "t": "string", "in": "body"},
            {"n": "organizationId", "t": "string", "in": "body"},
            {"n": "enabled", "t": "boolean", "in": "body"},
            {"n": "timezone", "t": "string", "in": "body"},
            {"n": "createdAt", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "security",
        "m": "POST",
        "p": "/security.create",
        "params": [
            {"n": "applicationId", "t": "string", "in": "body", "r": True},
            {"n": "username", "t": "string", "in": "body", "r": True},
            {"n": "password", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "security",
        "m": "POST",
        "p": "/security.delete",
        "params": [
            {"n": "securityId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "security",
        "m": "GET",
        "p": "/security.one",
        "params": [
            {"n": "securityId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "security",
        "m": "POST",
        "p": "/security.update",
        "params": [
            {"n": "securityId", "t": "string", "in": "body", "r": True},
            {"n": "username", "t": "string", "in": "body", "r": True},
            {"n": "password", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "server",
        "m": "GET",
        "p": "/server.all",
        "params": [],
    },
    {
        "tag": "server",
        "m": "GET",
        "p": "/server.allForPermissions",
        "params": [],
    },
    {
        "tag": "server",
        "m": "GET",
        "p": "/server.buildServers",
        "params": [],
    },
    {
        "tag": "server",
        "m": "GET",
        "p": "/server.count",
        "params": [],
    },
    {
        "tag": "server",
        "m": "POST",
        "p": "/server.create",
        "params": [
            {"n": "name", "t": "string", "in": "body", "r": True},
            {"n": "description", "t": "string", "in": "body", "r": True},
            {"n": "ipAddress", "t": "string", "in": "body", "r": True},
            {"n": "port", "t": "number", "in": "body", "r": True},
            {"n": "username", "t": "string", "in": "body", "r": True},
            {"n": "sshKeyId", "t": "string", "in": "body", "r": True},
            {"n": "serverType", "t": "string", "in": "body", "r": True, "e": ["deploy", "build"]},
            {"n": "enableDockerCleanup", "t": "boolean", "in": "body"},
        ],
    },
    {
        "tag": "server",
        "m": "GET",
        "p": "/server.getDefaultCommand",
        "params": [
            {"n": "serverId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "server",
        "m": "GET",
        "p": "/server.getServerMetrics",
        "params": [
            {"n": "url", "t": "string", "in": "query", "r": True},
            {"n": "token", "t": "string", "in": "query", "r": True},
            {"n": "dataPoints", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "server",
        "m": "GET",
        "p": "/server.getServerTime",
        "params": [],
    },
    {
        "tag": "server",
        "m": "GET",
        "p": "/server.one",
        "params": [
            {"n": "serverId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "server",
        "m": "GET",
        "p": "/server.publicIp",
        "params": [],
    },
    {
        "tag": "server",
        "m": "POST",
        "p": "/server.remove",
        "params": [
            {"n": "serverId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "server",
        "m": "GET",
        "p": "/server.security",
        "params": [
            {"n": "serverId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "server",
        "m": "POST",
        "p": "/server.setup",
        "params": [
            {"n": "serverId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "server",
        "m": "POST",
        "p": "/server.setupMonitoring",
        "params": [
            {"n": "serverId", "t": "string", "in": "body", "r": True},
            {"n": "metricsConfig", "t": "object", "in": "body", "r": True},
        ],
    },
    {
        "tag": "server",
        "m": "POST",
        "p": "/server.update",
        "params": [
            {"n": "name", "t": "string", "in": "body", "r": True},
            {"n": "description", "t": "string", "in": "body", "r": True},
            {"n": "serverId", "t": "string", "in": "body", "r": True},
            {"n": "ipAddress", "t": "string", "in": "body", "r": True},
            {"n": "port", "t": "number", "in": "body", "r": True},
            {"n": "username", "t": "string", "in": "body", "r": True},
            {"n": "sshKeyId", "t": "string", "in": "body", "r": True},
            {"n": "serverType", "t": "string", "in": "body", "r": True, "e": ["deploy", "build"]},
            {"n": "enableDockerCleanup", "t": "boolean", "in": "body"},
            {"n": "command", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "server",
        "m": "GET",
        "p": "/server.validate",
        "params": [
            {"n": "serverId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "server",
        "m": "GET",
        "p": "/server.withSSHKey",
        "params": [],
    },
    {
        "tag": "settings",
        "m": "POST",
        "p": "/settings.assignDomainServer",
        "params": [
            {"n": "host", "t": "string", "in": "body", "r": True},
            {"n": "certificateType", "t": "string", "in": "body", "r": True, "e": ["letsencrypt", "none", "custom"]},
            {"n": "letsEncryptEmail", "t": "string", "in": "body"},
            {"n": "https", "t": "boolean", "in": "body"},
        ],
    },
    {
        "tag": "settings",
        "m": "GET",
        "p": "/settings.checkGPUStatus",
        "params": [
            {"n": "serverId", "t": "string", "in": "query"},
        ],
    },
    {
        "tag": "settings",
        "m": "GET",
        "p": "/settings.checkInfrastructureHealth",
        "params": [],
    },
    {
        "tag": "settings",
        "m": "POST",
        "p": "/settings.cleanAll",
        "params": [
            {"n": "serverId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "settings",
        "m": "POST",
        "p": "/settings.cleanAllDeploymentQueue",
        "params": [],
    },
    {
        "tag": "settings",
        "m": "POST",
        "p": "/settings.cleanDockerBuilder",
        "params": [
            {"n": "serverId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "settings",
        "m": "POST",
        "p": "/settings.cleanDockerPrune",
        "params": [
            {"n": "serverId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "settings",
        "m": "POST",
        "p": "/settings.cleanMonitoring",
        "params": [],
    },
    {
        "tag": "settings",
        "m": "POST",
        "p": "/settings.cleanRedis",
        "params": [],
    },
    {
        "tag": "settings",
        "m": "POST",
        "p": "/settings.cleanSSHPrivateKey",
        "params": [],
    },
    {
        "tag": "settings",
        "m": "POST",
        "p": "/settings.cleanStoppedContainers",
        "params": [
            {"n": "serverId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "settings",
        "m": "POST",
        "p": "/settings.cleanUnusedImages",
        "params": [
            {"n": "serverId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "settings",
        "m": "POST",
        "p": "/settings.cleanUnusedVolumes",
        "params": [
            {"n": "serverId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "settings",
        "m": "GET",
        "p": "/settings.getDockerDiskUsage",
        "params": [],
    },
    {
        "tag": "settings",
        "m": "GET",
        "p": "/settings.getDokployCloudIps",
        "params": [],
    },
    {
        "tag": "settings",
        "m": "GET",
        "p": "/settings.getDokployVersion",
        "params": [],
    },
    {
        "tag": "settings",
        "m": "GET",
        "p": "/settings.getIp",
        "params": [],
    },
    {
        "tag": "settings",
        "m": "GET",
        "p": "/settings.getLogCleanupStatus",
        "params": [],
    },
    {
        "tag": "settings",
        "m": "GET",
        "p": "/settings.getOpenApiDocument",
        "params": [],
    },
    {
        "tag": "settings",
        "m": "GET",
        "p": "/settings.getReleaseTag",
        "params": [],
    },
    {
        "tag": "settings",
        "m": "GET",
        "p": "/settings.getTraefikPorts",
        "params": [
            {"n": "serverId", "t": "string", "in": "query"},
        ],
    },
    {
        "tag": "settings",
        "m": "POST",
        "p": "/settings.getUpdateData",
        "params": [],
    },
    {
        "tag": "settings",
        "m": "GET",
        "p": "/settings.getWebServerSettings",
        "params": [],
    },
    {
        "tag": "settings",
        "m": "GET",
        "p": "/settings.haveActivateRequests",
        "params": [],
    },
    {
        "tag": "settings",
        "m": "GET",
        "p": "/settings.haveTraefikDashboardPortEnabled",
        "params": [
            {"n": "serverId", "t": "string", "in": "query"},
        ],
    },
    {
        "tag": "settings",
        "m": "GET",
        "p": "/settings.health",
        "params": [],
    },
    {
        "tag": "settings",
        "m": "GET",
        "p": "/settings.isCloud",
        "params": [],
    },
    {
        "tag": "settings",
        "m": "GET",
        "p": "/settings.isUserSubscribed",
        "params": [],
    },
    {
        "tag": "settings",
        "m": "GET",
        "p": "/settings.readDirectories",
        "params": [
            {"n": "serverId", "t": "string", "in": "query"},
        ],
    },
    {
        "tag": "settings",
        "m": "GET",
        "p": "/settings.readMiddlewareTraefikConfig",
        "params": [],
    },
    {
        "tag": "settings",
        "m": "GET",
        "p": "/settings.readTraefikConfig",
        "params": [],
    },
    {
        "tag": "settings",
        "m": "GET",
        "p": "/settings.readTraefikEnv",
        "params": [
            {"n": "serverId", "t": "string", "in": "query"},
        ],
    },
    {
        "tag": "settings",
        "m": "GET",
        "p": "/settings.readTraefikFile",
        "params": [
            {"n": "path", "t": "string", "in": "query", "r": True},
            {"n": "serverId", "t": "string", "in": "query"},
        ],
    },
    {
        "tag": "settings",
        "m": "GET",
        "p": "/settings.readWebServerTraefikConfig",
        "params": [],
    },
    {
        "tag": "settings",
        "m": "POST",
        "p": "/settings.reloadRedis",
        "params": [],
    },
    {
        "tag": "settings",
        "m": "POST",
        "p": "/settings.reloadServer",
        "params": [],
    },
    {
        "tag": "settings",
        "m": "POST",
        "p": "/settings.reloadTraefik",
        "params": [
            {"n": "serverId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "settings",
        "m": "POST",
        "p": "/settings.saveSSHPrivateKey",
        "params": [
            {"n": "sshPrivateKey", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "settings",
        "m": "POST",
        "p": "/settings.setupGPU",
        "params": [
            {"n": "serverId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "settings",
        "m": "POST",
        "p": "/settings.toggleDashboard",
        "params": [
            {"n": "enableDashboard", "t": "boolean", "in": "body"},
            {"n": "serverId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "settings",
        "m": "POST",
        "p": "/settings.toggleRequests",
        "params": [
            {"n": "enable", "t": "boolean", "in": "body", "r": True},
        ],
    },
    {
        "tag": "settings",
        "m": "POST",
        "p": "/settings.updateDockerCleanup",
        "params": [
            {"n": "enableDockerCleanup", "t": "boolean", "in": "body", "r": True},
            {"n": "serverId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "settings",
        "m": "POST",
        "p": "/settings.updateEnforceSSO",
        "params": [
            {"n": "enforceSSO", "t": "boolean", "in": "body", "r": True},
        ],
    },
    {
        "tag": "settings",
        "m": "POST",
        "p": "/settings.updateLogCleanup",
        "params": [
            {"n": "cronExpression", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "settings",
        "m": "POST",
        "p": "/settings.updateMiddlewareTraefikConfig",
        "params": [
            {"n": "traefikConfig", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "settings",
        "m": "POST",
        "p": "/settings.updateRemoteServersOnly",
        "params": [
            {"n": "remoteServersOnly", "t": "boolean", "in": "body", "r": True},
        ],
    },
    {
        "tag": "settings",
        "m": "POST",
        "p": "/settings.updateServer",
        "params": [],
    },
    {
        "tag": "settings",
        "m": "POST",
        "p": "/settings.updateServerIp",
        "params": [
            {"n": "serverIp", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "settings",
        "m": "POST",
        "p": "/settings.updateTraefikConfig",
        "params": [
            {"n": "traefikConfig", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "settings",
        "m": "POST",
        "p": "/settings.updateTraefikFile",
        "params": [
            {"n": "path", "t": "string", "in": "body", "r": True},
            {"n": "traefikConfig", "t": "string", "in": "body", "r": True},
            {"n": "serverId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "settings",
        "m": "POST",
        "p": "/settings.updateTraefikPorts",
        "params": [
            {"n": "serverId", "t": "string", "in": "body"},
            {"n": "additionalPorts", "t": "array", "in": "body", "r": True},
        ],
    },
    {
        "tag": "settings",
        "m": "POST",
        "p": "/settings.updateWebServerTraefikConfig",
        "params": [
            {"n": "traefikConfig", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "settings",
        "m": "POST",
        "p": "/settings.writeTraefikEnv",
        "params": [
            {"n": "env", "t": "string", "in": "body", "r": True},
            {"n": "serverId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "sshKey",
        "m": "GET",
        "p": "/sshKey.all",
        "params": [],
    },
    {
        "tag": "sshKey",
        "m": "GET",
        "p": "/sshKey.allForApps",
        "params": [],
    },
    {
        "tag": "sshKey",
        "m": "POST",
        "p": "/sshKey.create",
        "params": [
            {"n": "name", "t": "string", "in": "body", "r": True},
            {"n": "description", "t": "string", "in": "body"},
            {"n": "privateKey", "t": "string", "in": "body", "r": True},
            {"n": "publicKey", "t": "string", "in": "body", "r": True},
            {"n": "organizationId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "sshKey",
        "m": "POST",
        "p": "/sshKey.generate",
        "params": [
            {"n": "type", "t": "string", "in": "body", "e": ["rsa", "ed25519"]},
        ],
    },
    {
        "tag": "sshKey",
        "m": "GET",
        "p": "/sshKey.one",
        "params": [
            {"n": "sshKeyId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "sshKey",
        "m": "POST",
        "p": "/sshKey.remove",
        "params": [
            {"n": "sshKeyId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "sshKey",
        "m": "POST",
        "p": "/sshKey.update",
        "params": [
            {"n": "name", "t": "string", "in": "body"},
            {"n": "description", "t": "string", "in": "body"},
            {"n": "lastUsedAt", "t": "string", "in": "body"},
            {"n": "sshKeyId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "sso",
        "m": "POST",
        "p": "/sso.addTrustedOrigin",
        "params": [
            {"n": "origin", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "sso",
        "m": "POST",
        "p": "/sso.deleteProvider",
        "params": [
            {"n": "providerId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "sso",
        "m": "GET",
        "p": "/sso.enforceSSO",
        "params": [],
    },
    {
        "tag": "sso",
        "m": "GET",
        "p": "/sso.getTrustedOrigins",
        "params": [],
    },
    {
        "tag": "sso",
        "m": "GET",
        "p": "/sso.listProviders",
        "params": [],
    },
    {
        "tag": "sso",
        "m": "GET",
        "p": "/sso.one",
        "params": [
            {"n": "providerId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "sso",
        "m": "POST",
        "p": "/sso.register",
        "params": [
            {"n": "providerId", "t": "string", "in": "body", "r": True},
            {"n": "issuer", "t": "string", "in": "body", "r": True},
            {"n": "domains", "t": "array", "in": "body", "r": True},
            {"n": "oidcConfig", "t": "object", "in": "body"},
            {"n": "samlConfig", "t": "object", "in": "body"},
            {"n": "organizationId", "t": "string", "in": "body"},
            {"n": "overrideUserInfo", "t": "boolean", "in": "body"},
        ],
    },
    {
        "tag": "sso",
        "m": "POST",
        "p": "/sso.removeTrustedOrigin",
        "params": [
            {"n": "origin", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "sso",
        "m": "GET",
        "p": "/sso.showSignInWithSSO",
        "params": [],
    },
    {
        "tag": "sso",
        "m": "POST",
        "p": "/sso.update",
        "params": [
            {"n": "providerId", "t": "string", "in": "body", "r": True},
            {"n": "issuer", "t": "string", "in": "body", "r": True},
            {"n": "domains", "t": "array", "in": "body", "r": True},
            {"n": "oidcConfig", "t": "object", "in": "body"},
            {"n": "samlConfig", "t": "object", "in": "body"},
            {"n": "organizationId", "t": "string", "in": "body"},
            {"n": "overrideUserInfo", "t": "boolean", "in": "body"},
        ],
    },
    {
        "tag": "sso",
        "m": "POST",
        "p": "/sso.updateTrustedOrigin",
        "params": [
            {"n": "oldOrigin", "t": "string", "in": "body", "r": True},
            {"n": "newOrigin", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "stripe",
        "m": "GET",
        "p": "/stripe.canCreateMoreServers",
        "params": [],
    },
    {
        "tag": "stripe",
        "m": "POST",
        "p": "/stripe.createCheckoutSession",
        "params": [
            {"n": "tier", "t": "string", "in": "body", "r": True, "e": ["legacy", "hobby", "startup"]},
            {"n": "productId", "t": "string", "in": "body", "r": True},
            {"n": "serverQuantity", "t": "number", "in": "body", "r": True},
            {"n": "isAnnual", "t": "boolean", "in": "body", "r": True},
        ],
    },
    {
        "tag": "stripe",
        "m": "POST",
        "p": "/stripe.createCustomerPortalSession",
        "params": [],
    },
    {
        "tag": "stripe",
        "m": "GET",
        "p": "/stripe.getCurrentPlan",
        "params": [],
    },
    {
        "tag": "stripe",
        "m": "GET",
        "p": "/stripe.getInvoices",
        "params": [],
    },
    {
        "tag": "stripe",
        "m": "GET",
        "p": "/stripe.getProducts",
        "params": [],
    },
    {
        "tag": "stripe",
        "m": "POST",
        "p": "/stripe.updateInvoiceNotifications",
        "params": [
            {"n": "enabled", "t": "boolean", "in": "body", "r": True},
        ],
    },
    {
        "tag": "stripe",
        "m": "POST",
        "p": "/stripe.upgradeSubscription",
        "params": [
            {"n": "tier", "t": "string", "in": "body", "r": True, "e": ["hobby", "startup"]},
            {"n": "serverQuantity", "t": "number", "in": "body", "r": True},
            {"n": "isAnnual", "t": "boolean", "in": "body", "r": True},
        ],
    },
    {
        "tag": "swarm",
        "m": "GET",
        "p": "/swarm.getContainerStats",
        "params": [
            {"n": "serverId", "t": "string", "in": "query"},
        ],
    },
    {
        "tag": "swarm",
        "m": "GET",
        "p": "/swarm.getNodeApps",
        "params": [
            {"n": "serverId", "t": "string", "in": "query"},
        ],
    },
    {
        "tag": "swarm",
        "m": "GET",
        "p": "/swarm.getNodeInfo",
        "params": [
            {"n": "nodeId", "t": "string", "in": "query", "r": True},
            {"n": "serverId", "t": "string", "in": "query"},
        ],
    },
    {
        "tag": "swarm",
        "m": "GET",
        "p": "/swarm.getNodes",
        "params": [
            {"n": "serverId", "t": "string", "in": "query"},
        ],
    },
    {
        "tag": "tag",
        "m": "GET",
        "p": "/tag.all",
        "params": [],
    },
    {
        "tag": "tag",
        "m": "POST",
        "p": "/tag.assignToProject",
        "params": [
            {"n": "projectId", "t": "string", "in": "body", "r": True},
            {"n": "tagId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "tag",
        "m": "POST",
        "p": "/tag.bulkAssign",
        "params": [
            {"n": "projectId", "t": "string", "in": "body", "r": True},
            {"n": "tagIds", "t": "array", "in": "body", "r": True},
        ],
    },
    {
        "tag": "tag",
        "m": "POST",
        "p": "/tag.create",
        "params": [
            {"n": "name", "t": "string", "in": "body", "r": True},
            {"n": "color", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "tag",
        "m": "GET",
        "p": "/tag.one",
        "params": [
            {"n": "tagId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "tag",
        "m": "POST",
        "p": "/tag.remove",
        "params": [
            {"n": "tagId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "tag",
        "m": "POST",
        "p": "/tag.removeFromProject",
        "params": [
            {"n": "projectId", "t": "string", "in": "body", "r": True},
            {"n": "tagId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "tag",
        "m": "POST",
        "p": "/tag.update",
        "params": [
            {"n": "tagId", "t": "string", "in": "body", "r": True},
            {"n": "name", "t": "string", "in": "body"},
            {"n": "color", "t": "string", "in": "body"},
            {"n": "createdAt", "t": "string", "in": "body"},
            {"n": "organizationId", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "user",
        "m": "GET",
        "p": "/user.all",
        "params": [],
    },
    {
        "tag": "user",
        "m": "POST",
        "p": "/user.assignPermissions",
        "params": [
            {"n": "id", "t": "string", "in": "body", "r": True},
            {"n": "accessedProjects", "t": "array", "in": "body", "r": True},
            {"n": "accessedEnvironments", "t": "array", "in": "body", "r": True},
            {"n": "accessedServices", "t": "array", "in": "body", "r": True},
            {"n": "accessedGitProviders", "t": "array", "in": "body", "r": True},
            {"n": "accessedServers", "t": "array", "in": "body", "r": True},
            {"n": "canCreateProjects", "t": "boolean", "in": "body", "r": True},
            {"n": "canCreateServices", "t": "boolean", "in": "body", "r": True},
            {"n": "canDeleteProjects", "t": "boolean", "in": "body", "r": True},
            {"n": "canDeleteServices", "t": "boolean", "in": "body", "r": True},
            {"n": "canAccessToDocker", "t": "boolean", "in": "body", "r": True},
            {"n": "canAccessToTraefikFiles", "t": "boolean", "in": "body", "r": True},
            {"n": "canAccessToAPI", "t": "boolean", "in": "body", "r": True},
            {"n": "canAccessToSSHKeys", "t": "boolean", "in": "body", "r": True},
            {"n": "canAccessToGitProviders", "t": "boolean", "in": "body", "r": True},
            {"n": "canDeleteEnvironments", "t": "boolean", "in": "body", "r": True},
            {"n": "canCreateEnvironments", "t": "boolean", "in": "body", "r": True},
        ],
    },
    {
        "tag": "user",
        "m": "GET",
        "p": "/user.checkUserOrganizations",
        "params": [
            {"n": "userId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "user",
        "m": "POST",
        "p": "/user.createApiKey",
        "params": [
            {"n": "name", "t": "string", "in": "body", "r": True},
            {"n": "prefix", "t": "string", "in": "body"},
            {"n": "expiresIn", "t": "number", "in": "body"},
            {"n": "metadata", "t": "object", "in": "body", "r": True},
            {"n": "rateLimitEnabled", "t": "boolean", "in": "body"},
            {"n": "rateLimitTimeWindow", "t": "number", "in": "body"},
            {"n": "rateLimitMax", "t": "number", "in": "body"},
            {"n": "remaining", "t": "number", "in": "body"},
            {"n": "refillAmount", "t": "number", "in": "body"},
            {"n": "refillInterval", "t": "number", "in": "body"},
        ],
    },
    {
        "tag": "user",
        "m": "POST",
        "p": "/user.createUserWithCredentials",
        "params": [
            {"n": "email", "t": "string", "in": "body", "r": True},
            {"n": "password", "t": "string", "in": "body", "r": True},
            {"n": "role", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "user",
        "m": "POST",
        "p": "/user.deleteApiKey",
        "params": [
            {"n": "apiKeyId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "user",
        "m": "POST",
        "p": "/user.generateToken",
        "params": [],
    },
    {
        "tag": "user",
        "m": "GET",
        "p": "/user.get",
        "params": [],
    },
    {
        "tag": "user",
        "m": "GET",
        "p": "/user.getBackups",
        "params": [],
    },
    {
        "tag": "user",
        "m": "GET",
        "p": "/user.getBookmarkedTemplates",
        "params": [],
    },
    {
        "tag": "user",
        "m": "GET",
        "p": "/user.getContainerMetrics",
        "params": [
            {"n": "url", "t": "string", "in": "query", "r": True},
            {"n": "token", "t": "string", "in": "query", "r": True},
            {"n": "appName", "t": "string", "in": "query", "r": True},
            {"n": "dataPoints", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "user",
        "m": "GET",
        "p": "/user.getInvitations",
        "params": [],
    },
    {
        "tag": "user",
        "m": "GET",
        "p": "/user.getMetricsToken",
        "params": [],
    },
    {
        "tag": "user",
        "m": "GET",
        "p": "/user.getPermissions",
        "params": [],
    },
    {
        "tag": "user",
        "m": "GET",
        "p": "/user.getServerMetrics",
        "params": [],
    },
    {
        "tag": "user",
        "m": "GET",
        "p": "/user.getUserByToken",
        "params": [
            {"n": "token", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "user",
        "m": "GET",
        "p": "/user.haveRootAccess",
        "params": [],
    },
    {
        "tag": "user",
        "m": "GET",
        "p": "/user.one",
        "params": [
            {"n": "userId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "user",
        "m": "POST",
        "p": "/user.remove",
        "params": [
            {"n": "userId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "user",
        "m": "POST",
        "p": "/user.sendInvitation",
        "params": [
            {"n": "invitationId", "t": "string", "in": "body", "r": True},
            {"n": "notificationId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "user",
        "m": "GET",
        "p": "/user.session",
        "params": [],
    },
    {
        "tag": "user",
        "m": "POST",
        "p": "/user.toggleTemplateBookmark",
        "params": [
            {"n": "templateId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "user",
        "m": "POST",
        "p": "/user.update",
        "params": [
            {"n": "id", "t": "string", "in": "body"},
            {"n": "firstName", "t": "string", "in": "body"},
            {"n": "lastName", "t": "string", "in": "body"},
            {"n": "isRegistered", "t": "boolean", "in": "body"},
            {"n": "expirationDate", "t": "string", "in": "body"},
            {"n": "createdAt2", "t": "string", "in": "body"},
            {"n": "createdAt", "t": "string", "in": "body"},
            {"n": "twoFactorEnabled", "t": "boolean", "in": "body"},
            {"n": "email", "t": "string", "in": "body"},
            {"n": "emailVerified", "t": "boolean", "in": "body"},
            {"n": "image", "t": "string", "in": "body"},
            {"n": "banned", "t": "boolean", "in": "body"},
            {"n": "banReason", "t": "string", "in": "body"},
            {"n": "banExpires", "t": "string", "in": "body"},
            {"n": "updatedAt", "t": "string", "in": "body"},
            {"n": "enablePaidFeatures", "t": "boolean", "in": "body"},
            {"n": "allowImpersonation", "t": "boolean", "in": "body"},
            {"n": "enableEnterpriseFeatures", "t": "boolean", "in": "body"},
            {"n": "licenseKey", "t": "string", "in": "body"},
            {"n": "stripeCustomerId", "t": "string", "in": "body"},
            {"n": "stripeSubscriptionId", "t": "string", "in": "body"},
            {"n": "serversQuantity", "t": "number", "in": "body"},
            {"n": "sendInvoiceNotifications", "t": "boolean", "in": "body"},
            {"n": "password", "t": "string", "in": "body"},
            {"n": "currentPassword", "t": "string", "in": "body"},
        ],
    },
    {
        "tag": "volumeBackups",
        "m": "POST",
        "p": "/volumeBackups.create",
        "params": [
            {"n": "name", "t": "string", "in": "body", "r": True},
            {"n": "volumeName", "t": "string", "in": "body", "r": True},
            {"n": "prefix", "t": "string", "in": "body", "r": True},
            {"n": "serviceType", "t": "string", "in": "body", "e": ["application", "postgres", "mysql", "mariadb", "mongo", "redis", "compose", "libsql"]},
            {"n": "appName", "t": "string", "in": "body"},
            {"n": "serviceName", "t": "string", "in": "body"},
            {"n": "turnOff", "t": "boolean", "in": "body"},
            {"n": "cronExpression", "t": "string", "in": "body", "r": True},
            {"n": "keepLatestCount", "t": "number", "in": "body"},
            {"n": "enabled", "t": "boolean", "in": "body"},
            {"n": "applicationId", "t": "string", "in": "body"},
            {"n": "postgresId", "t": "string", "in": "body"},
            {"n": "mariadbId", "t": "string", "in": "body"},
            {"n": "mongoId", "t": "string", "in": "body"},
            {"n": "mysqlId", "t": "string", "in": "body"},
            {"n": "redisId", "t": "string", "in": "body"},
            {"n": "libsqlId", "t": "string", "in": "body"},
            {"n": "composeId", "t": "string", "in": "body"},
            {"n": "createdAt", "t": "string", "in": "body"},
            {"n": "destinationId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "volumeBackups",
        "m": "POST",
        "p": "/volumeBackups.delete",
        "params": [
            {"n": "volumeBackupId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "volumeBackups",
        "m": "GET",
        "p": "/volumeBackups.list",
        "params": [
            {"n": "id", "t": "string", "in": "query", "r": True},
            {"n": "volumeBackupType", "t": "string", "in": "query", "r": True, "e": ["application", "postgres", "mysql", "mariadb", "mongo", "redis", "compose", "libsql"]},
        ],
    },
    {
        "tag": "volumeBackups",
        "m": "GET",
        "p": "/volumeBackups.one",
        "params": [
            {"n": "volumeBackupId", "t": "string", "in": "query", "r": True},
        ],
    },
    {
        "tag": "volumeBackups",
        "m": "POST",
        "p": "/volumeBackups.runManually",
        "params": [
            {"n": "volumeBackupId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "volumeBackups",
        "m": "POST",
        "p": "/volumeBackups.update",
        "params": [
            {"n": "name", "t": "string", "in": "body", "r": True},
            {"n": "volumeName", "t": "string", "in": "body", "r": True},
            {"n": "prefix", "t": "string", "in": "body", "r": True},
            {"n": "serviceType", "t": "string", "in": "body", "e": ["application", "postgres", "mysql", "mariadb", "mongo", "redis", "compose", "libsql"]},
            {"n": "appName", "t": "string", "in": "body"},
            {"n": "serviceName", "t": "string", "in": "body"},
            {"n": "turnOff", "t": "boolean", "in": "body"},
            {"n": "cronExpression", "t": "string", "in": "body", "r": True},
            {"n": "keepLatestCount", "t": "number", "in": "body"},
            {"n": "enabled", "t": "boolean", "in": "body"},
            {"n": "applicationId", "t": "string", "in": "body"},
            {"n": "postgresId", "t": "string", "in": "body"},
            {"n": "mariadbId", "t": "string", "in": "body"},
            {"n": "mongoId", "t": "string", "in": "body"},
            {"n": "mysqlId", "t": "string", "in": "body"},
            {"n": "redisId", "t": "string", "in": "body"},
            {"n": "libsqlId", "t": "string", "in": "body"},
            {"n": "composeId", "t": "string", "in": "body"},
            {"n": "createdAt", "t": "string", "in": "body"},
            {"n": "destinationId", "t": "string", "in": "body", "r": True},
            {"n": "volumeBackupId", "t": "string", "in": "body", "r": True},
        ],
    },
    {
        "tag": "whitelabeling",
        "m": "GET",
        "p": "/whitelabeling.get",
        "params": [],
    },
    {
        "tag": "whitelabeling",
        "m": "GET",
        "p": "/whitelabeling.getPublic",
        "params": [],
    },
    {
        "tag": "whitelabeling",
        "m": "POST",
        "p": "/whitelabeling.reset",
        "params": [],
    },
    {
        "tag": "whitelabeling",
        "m": "POST",
        "p": "/whitelabeling.update",
        "params": [
            {"n": "whitelabelingConfig", "t": "object", "in": "body", "r": True},
        ],
    },
]


def error_exit(msg: str):
    """Print JSON error to stderr and exit."""
    print(json.dumps({"success": False, "error": msg}), file=sys.stderr)
    sys.exit(1)


def to_kebab(name: str) -> str:
    """Convert camelCase to kebab-case: sshKey -> ssh-key, customGitSSHKeyId -> custom-git-ssh-key-id."""
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1-\2", name)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1-\2", s).lower()


_BOOL_TRUE = frozenset({"true", "1", "yes", "on"})
_BOOL_FALSE = frozenset({"false", "0", "no", "off"})
_SENSITIVE_KEYS = frozenset(
    {"apikey", "api_key", "password", "secret", "token", "privatekey"}
)


def coerce_param(value: str, param_type: str):
    """Coerce CLI string values to API parameter types."""
    if param_type == "boolean":
        low = value.lower()
        if low in _BOOL_TRUE:
            return True
        if low in _BOOL_FALSE:
            return False
        raise ValueError(
            f"invalid boolean '{value}' (expected: true/false, yes/no, 1/0, on/off)"
        )
    if param_type == "integer":
        f = float(value)
        if not math.isfinite(f):
            raise ValueError(f"invalid integer '{value}' (nan/inf not allowed)")
        if not f.is_integer():
            raise ValueError(
                f"invalid integer '{value}' (got decimal; use a whole number)"
            )
        return int(f)
    if param_type == "number":
        f = float(value)
        if not math.isfinite(f):
            raise ValueError(f"invalid number '{value}' (nan/inf not allowed)")
        return int(f) if f == int(f) and "." not in value else f
    if param_type in ("array", "object"):
        return json.loads(value)
    return value


def _redact_url(url: str) -> str:
    """Strip query string from URL to prevent leaking sensitive params."""
    return url.split("?")[0]


def _redact_detail(detail):
    """Recursively redact sensitive keys from error detail."""
    if isinstance(detail, dict):
        return {
            k: (
                "***"
                if k.lower().replace("-", "").replace("_", "") in _SENSITIVE_KEYS
                else _redact_detail(v)
            )
            for k, v in detail.items()
        }
    if isinstance(detail, list):
        return [_redact_detail(item) for item in detail]
    return detail


class DokployClient:
    def __init__(self, base_url: str, api_key: str, timeout: float = 60.0):
        self.client = httpx.Client(
            base_url=base_url.rstrip("/") + "/api",
            headers={"x-api-key": api_key},
            timeout=timeout,
        )

    def call(
        self,
        method: str,
        path: str,
        params: dict | None = None,
        body: dict | None = None,
        files: dict | None = None,
    ) -> dict:
        """Execute API call with retry on 5xx."""
        max_retries = 2
        for attempt in range(max_retries + 1):
            opened = None
            try:
                if method == "GET":
                    resp = self.client.get(path, params=params)
                elif files:
                    # multipart/form-data upload (e.g. application.dropDeployment,
                    # docker.uploadFileToContainer): body fields are sent as form
                    # data, file params as streams. Open incrementally so a later
                    # failure can't leak earlier handles.
                    opened = {}
                    try:
                        for _n, _fp in files.items():
                            opened[_n] = open(_fp, "rb")
                    except OSError as e:
                        for _fh in opened.values():
                            _fh.close()
                        error_exit(f"Cannot open file: {e}")
                    resp = self.client.post(
                        path, params=params, data=body or {}, files=opened
                    )
                else:
                    resp = self.client.post(
                        path, params=params, json=body if body is not None else {}
                    )

                if opened:
                    for _fh in opened.values():
                        _fh.close()
                    opened = None

                if resp.status_code >= 500 and attempt < max_retries:
                    import time

                    time.sleep(1 * (attempt + 1))
                    continue

                resp.raise_for_status()

                try:
                    return resp.json()
                except Exception:
                    return {"raw": resp.text}
            except httpx.HTTPStatusError as e:
                error_body = ""
                try:
                    error_body = _redact_detail(e.response.json())
                except Exception:
                    error_body = e.response.text[:500]
                raise SystemExit(
                    json.dumps(
                        {
                            "success": False,
                            "error": f"{e.response.status_code} {e.response.reason_phrase} for {_redact_url(str(e.request.url))}",
                            "status_code": e.response.status_code,
                            "detail": error_body,
                        }
                    )
                )
            except httpx.RequestError as e:
                if opened:
                    for _fh in opened.values():
                        _fh.close()
                    opened = None
                if attempt < max_retries:
                    import time

                    time.sleep(1 * (attempt + 1))
                    continue
                raise SystemExit(
                    json.dumps({"success": False, "error": f"Request failed: {e}"})
                )

        raise SystemExit(
            json.dumps({"success": False, "error": "Max retries exceeded"})
        )

    def close(self):
        self.client.close()


def endpoint_action(path: str) -> str:
    """Extract action from /tag.action path."""
    dot = path.rsplit(".", 1)
    return dot[1] if len(dot) == 2 else path.strip("/")


def param_help(param: dict) -> str:
    """Build argparse help text for one parameter."""
    pieces = [f"type={param.get('t', 'string')}", f"in={param.get('in', 'body')}"]
    if param.get("r") is True:
        pieces.append("required")
    if "e" in param:
        pieces.append(f"enum={param['e']}")
    if "d" in param:
        pieces.append(f"default={param['d']}")
    return ", ".join(pieces)


def build_parser() -> argparse.ArgumentParser:
    """Create hierarchical CLI parser from endpoint registry."""
    parser = argparse.ArgumentParser(description="Dokploy CLI for REST API endpoints")
    parser.add_argument("--raw", action="store_true", help="Output raw API response")
    parser.add_argument(
        "--timeout", type=float, default=60.0, help="HTTP timeout in seconds"
    )

    # Use underscore-prefixed dests so they can never collide with an API param
    # named "domain" or "action" (e.g. domain.validateDomain, auditLog.all).
    domain_subparsers = parser.add_subparsers(dest="_domain")

    endpoints_by_domain = {}
    for endpoint in ENDPOINTS:
        domain = to_kebab(endpoint["tag"])
        endpoints_by_domain.setdefault(domain, []).append(endpoint)

    for domain in sorted(endpoints_by_domain):
        domain_parser = domain_subparsers.add_parser(domain, help=f"{domain} endpoints")
        domain_parser.set_defaults(_domain_parser=domain_parser)
        action_subparsers = domain_parser.add_subparsers(dest="_action")

        for endpoint in endpoints_by_domain[domain]:
            action = endpoint_action(endpoint["p"])
            action_parser = action_subparsers.add_parser(
                action, help=f"{endpoint['m']} {endpoint['p']}"
            )
            action_parser.set_defaults(_endpoint=endpoint)

            for param in endpoint.get("params", []):
                flag = f"--{to_kebab(param['n'])}"
                kwargs = {
                    "dest": param["n"],
                    "type": str,
                    "required": bool(param.get("r", False)),
                    "help": param_help(param),
                }
                if "e" in param:
                    kwargs["choices"] = [str(v) for v in param["e"]]
                if "d" in param:
                    kwargs["default"] = str(param["d"])
                action_parser.add_argument(flag, **kwargs)

    return parser


def build_payload(
    args: argparse.Namespace, endpoint: dict
) -> tuple[dict | None, dict | None, dict | None]:
    """Build query/body/file payloads from parsed CLI args and endpoint metadata."""
    query: dict = {}
    body: dict = {}
    files: dict = {}

    for param in endpoint.get("params", []):
        name = param["n"]
        raw_value = getattr(args, name, None)
        if raw_value is None:
            continue

        ptype = param.get("t", "string")
        if ptype == "file":
            # Value is a local file path; opened and streamed in DokployClient.call.
            files[name] = raw_value
            continue

        value = raw_value
        try:
            value = coerce_param(raw_value, ptype)
        except Exception as e:
            error_exit(f"Invalid value for {name}: {e}")

        if param.get("in") == "query":
            query[name] = value
        else:
            body[name] = value

    return (query or None), (body or None), (files or None)


def main():
    """CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args()

    if not getattr(args, "_domain", None):
        parser.print_help()
        sys.exit(2)

    if not getattr(args, "_action", None):
        domain_parser = getattr(args, "_domain_parser", None)
        if domain_parser:
            domain_parser.print_help()
        else:
            parser.print_help()
        sys.exit(2)

    endpoint = getattr(args, "_endpoint", None)
    if not endpoint:
        error_exit("Endpoint not found")
    assert endpoint is not None

    base_url = os.getenv("DOKPLOY_URL")
    api_key = os.getenv("DOKPLOY_API_KEY")

    if not base_url:
        error_exit("Missing DOKPLOY_URL environment variable")
    if not api_key:
        error_exit("Missing DOKPLOY_API_KEY environment variable")
    assert base_url is not None
    assert api_key is not None

    query_params, body, files = build_payload(args, endpoint)
    client = DokployClient(base_url, api_key, timeout=args.timeout)
    try:
        result = client.call(
            endpoint["m"], endpoint["p"], params=query_params, body=body, files=files
        )
        if args.raw:
            print(json.dumps(result, indent=2, default=str))
        else:
            print(json.dumps({"success": True, "data": result}, indent=2, default=str))
    finally:
        client.close()


if __name__ == "__main__":
    main()
