{
  "targets": [
    {
      "target_name": "secure_wiper",
      "sources": [ "src/cpp/addon.cpp" ],
      "include_dirs": [
        "D:/secure-wipe-dashboard/node_modules/node-addon-api"
      ],
      "dependencies": [
        "<!(node -p \"require('node-addon-api').gyp\")"
      ],
      "defines": [ "NAPI_DISABLE_CPP_EXCEPTIONS" ]
    }
  ]
}
