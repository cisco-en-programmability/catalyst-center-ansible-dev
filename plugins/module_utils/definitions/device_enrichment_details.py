import json

module_definition = json.loads('''{
    "family": "devices",
    "name": "device_enrichment_details",
    "operations": {
        "get": [
            "get_device_enrichment_details"
        ]
    },
    "parameters": {
        "get_device_enrichment_details": [
            {
                "name": "headers",
                "required": true,
                "schema": [],
                "type": "object"
            }
        ]
    },
    "responses": {
        "get_device_enrichment_details": {
            "array_type": "object",
            "properties": [
                "deviceDetails"
            ],
            "type": "array"
        }
    }
}''')