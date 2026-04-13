"""
Microsoft Sentinel integration — generate an Azure Logic App ARM template.

The generated playbook triggers on Sentinel incidents and forwards entity/tactic
data to nur's webhook endpoint.

Usage:
    from nur.integrations.sentinel import generate_sentinel_playbook
    arm_json = generate_sentinel_playbook("https://nur.example.com", "nur_abc123...")
    with open("sentinel_playbook.json", "w") as f:
        f.write(arm_json)
"""
from __future__ import annotations

import json


def generate_sentinel_playbook(api_url: str, api_key: str) -> str:
    """Generate Azure Logic App ARM template for Sentinel integration.

    Returns JSON string of the ARM template. Deploy with:
        az deployment group create -g <rg> --template-file sentinel_playbook.json
    """
    api_url = api_url.rstrip("/")

    template = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {
            "PlaybookName": {
                "type": "string",
                "defaultValue": "nur-sentinel-playbook",
                "metadata": {"description": "Name of the Logic App"},
            },
            "NurApiUrl": {
                "type": "string",
                "defaultValue": api_url,
                "metadata": {"description": "nur API base URL"},
            },
            "NurApiKey": {
                "type": "securestring",
                "defaultValue": api_key,
                "metadata": {"description": "nur API key for authentication"},
            },
        },
        "variables": {
            "AzureSentinelConnectionName": "[concat('azuresentinel-', parameters('PlaybookName'))]",
        },
        "resources": [
            # API connection for Sentinel
            {
                "type": "Microsoft.Web/connections",
                "apiVersion": "2016-06-01",
                "name": "[variables('AzureSentinelConnectionName')]",
                "location": "[resourceGroup().location]",
                "properties": {
                    "displayName": "[variables('AzureSentinelConnectionName')]",
                    "customParameterValues": {},
                    "api": {
                        "id": "[concat('/subscriptions/', subscription().subscriptionId, '/providers/Microsoft.Web/locations/', resourceGroup().location, '/managedApis/azuresentinel')]",
                    },
                },
            },
            # Logic App
            {
                "type": "Microsoft.Logic/workflows",
                "apiVersion": "2017-07-01",
                "name": "[parameters('PlaybookName')]",
                "location": "[resourceGroup().location]",
                "dependsOn": [
                    "[resourceId('Microsoft.Web/connections', variables('AzureSentinelConnectionName'))]",
                ],
                "properties": {
                    "state": "Enabled",
                    "definition": {
                        "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
                        "contentVersion": "1.0.0.0",
                        "parameters": {
                            "$connections": {
                                "defaultValue": {},
                                "type": "Object",
                            },
                        },
                        "triggers": {
                            "Microsoft_Sentinel_incident": {
                                "type": "ApiConnectionWebhook",
                                "inputs": {
                                    "body": {
                                        "callback_url": "@{listCallbackUrl()}",
                                    },
                                    "host": {
                                        "connection": {
                                            "name": "@parameters('$connections')['azuresentinel']['connectionId']",
                                        },
                                    },
                                    "path": "/incident-creation",
                                },
                            },
                        },
                        "actions": {
                            "Parse_Incident": {
                                "type": "ParseJson",
                                "runAfter": {},
                                "inputs": {
                                    "content": "@triggerBody()",
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "object": {
                                                "type": "object",
                                                "properties": {
                                                    "properties": {
                                                        "type": "object",
                                                        "properties": {
                                                            "severity": {"type": "string"},
                                                            "title": {"type": "string"},
                                                            "description": {"type": "string"},
                                                            "additionalData": {
                                                                "type": "object",
                                                                "properties": {
                                                                    "tactics": {
                                                                        "type": "array",
                                                                        "items": {"type": "string"},
                                                                    },
                                                                    "techniques": {
                                                                        "type": "array",
                                                                        "items": {"type": "string"},
                                                                    },
                                                                },
                                                            },
                                                        },
                                                    },
                                                },
                                            },
                                        },
                                    },
                                },
                            },
                            "Entities_-_Get_IPs": {
                                "type": "ApiConnection",
                                "runAfter": {"Parse_Incident": ["Succeeded"]},
                                "inputs": {
                                    "body": "@triggerBody()?['object']?['properties']?['relatedEntities']",
                                    "host": {
                                        "connection": {
                                            "name": "@parameters('$connections')['azuresentinel']['connectionId']",
                                        },
                                    },
                                    "method": "post",
                                    "path": "/entities/ip",
                                },
                            },
                            "Build_Entity_List": {
                                "type": "Compose",
                                "runAfter": {"Entities_-_Get_IPs": ["Succeeded"]},
                                "inputs": "@union(\n  if(equals(body('Entities_-_Get_IPs')?['IPs'], null), json('[]'),\n    body('Entities_-_Get_IPs')?['IPs']),\n  json('[]')\n)",
                            },
                            "Post_to_nur": {
                                "type": "Http",
                                "runAfter": {"Build_Entity_List": ["Succeeded"]},
                                "inputs": {
                                    "method": "POST",
                                    "uri": "[concat(parameters('NurApiUrl'), '/ingest/webhook')]",
                                    "headers": {
                                        "Content-Type": "application/json",
                                        "X-API-Key": "[parameters('NurApiKey')]",
                                    },
                                    "body": {
                                        "properties": {
                                            "severity": "@{body('Parse_Incident')?['object']?['properties']?['severity']}",
                                            "title": "@{body('Parse_Incident')?['object']?['properties']?['title']}",
                                            "tactics": "@body('Parse_Incident')?['object']?['properties']?['additionalData']?['tactics']",
                                            "techniques": "@body('Parse_Incident')?['object']?['properties']?['additionalData']?['techniques']",
                                            "entities": "@body('Build_Entity_List')",
                                        },
                                    },
                                },
                            },
                        },
                        "outputs": {},
                    },
                    "parameters": {
                        "$connections": {
                            "value": {
                                "azuresentinel": {
                                    "connectionId": "[resourceId('Microsoft.Web/connections', variables('AzureSentinelConnectionName'))]",
                                    "connectionName": "[variables('AzureSentinelConnectionName')]",
                                    "id": "[concat('/subscriptions/', subscription().subscriptionId, '/providers/Microsoft.Web/locations/', resourceGroup().location, '/managedApis/azuresentinel')]",
                                },
                            },
                        },
                    },
                },
            },
        ],
        "outputs": {
            "logicAppUrl": {
                "type": "string",
                "value": "[listCallbackUrl(resourceId('Microsoft.Logic/workflows/triggers', parameters('PlaybookName'), 'Microsoft_Sentinel_incident'), '2017-07-01').value]",
            },
        },
    }

    return json.dumps(template, indent=2)
