# MaxSecurityWAF

## This is the group 43 Web Application Firewall project.

## Prerequesites
### Download WebGoat .jar
https://github.com/WebGoat/WebGoat/releases/tag/v2023.4

## Running from source

### Start WebGoat
`java '-Dfile.encoding=UTF-8' '-Dwebgoat.port=8080' '-Dwebwolf.port=9090' -jar webgoat-2023.4.jar`

### Start the project
Open up http://127.0.0.1:8080/WebGoat to access webgoat.

http://127.0.0.1:5000/Login for the admin page.

## Release installation:
To install the MaxSecurityWAF application, the following steps are to be performed:

The latest Windows or Linux binaries can be downloaded from the GitHub page:
https://github.com/Da2MinuteNoodle/MaxSecurityWAF/releases/latest

### Windows Installation
1. Unzip the downloaded release .zip file into a specified folder.
2. To launch the MaxSecurityWAF web application firewall & WebGoat web server at the same time, run the launch.bat file as administrator.
3. Open a web browser and navigate to http://127.0.0.1:5000/ 

#### Individual Launch:

_MaxSecurityWAF_ - Launch the `MaxSecurityWAF.exe` file

_WebGoat_ - Launch a cmd window in the folder with the `webgoat-2023.4.jar` file, and run the command:
`java -Dfile.encoding=UTF-8 -Dwebgoat.port=8080 -Dwebwolf.port=9090 -jar webgoat-2023.4.jar`

### Linux Installation
1. Unzip the downloaded release .zip file into a specified folder.
2. To launch the MaxSecurityWAF web application firewall, launch the ./MaxSecurityWAF file in a command-line window
3. To launch WebGoat, run the following command in another command-line window:
`java -Dfile.encoding=UTF-8 -Dwebgoat.port=8080 -Dwebwolf.port=9090 -jar webgoat-2023.4.jar`
4. Open a web browser and navigate to http://127.0.0.1:5000/ 

## Configuration
### WebGoat Addresses
If hosting webgoat on a separate machine, the appsettings.json file will need to be edited to change the webgoat destination address:
```json
"Clusters": {
  "webgoatcluster": {
	"Destinations": {
	  "webgoat": {
		"Address:": "http://127.0.0.1:8080"
	  }
	}
  }
}
```

### SSL (HTTPS)
If running the WAF as the direct endpoint for external users, using HTTPS is recommended. To configure the WAF to start with HTTPS, the appsettings.json file will need to be edited as follows to add in the details of the SSL certificate to be used (provided by the end user):
```json
"Kestrel": {
    "Endpoints": {
      "Http": {
        "Url": "http://0.0.0.0:5000"
      },
	  "Https": {
		"Url": "https://0.0.0.0:5000"
		"Certificate": {
			"Path": "<path to .pem/.crt file>",
			"KeyPath": "<path to .key file>",
			"Password": "$CREDENTIAL_PLACEHOLDER$"
		}
	  }
    }
```

### Firewall (Windows Only)
To allow access to the WAF from external devices, the .exe file will need to be allowed in the Windows firewall along with an inbound port of 5000.

## Default Credentials
The default credentials for the MaxSecurityWAF are
__Username__: admin
__Password__: admin
