
# APIP - API Automation for bad IPs

This opensource project , its uses several free CyberSec APIs and data analysis techniques to output in visual way trough a WebApp ,  API responses on malicious IPs .

With APIP its possible to do corelation and OSINT on IPs in fast and precisous way. 





![Logo](https://i.ibb.co/dDxyhnr/cooltext399694882765997.png)



## Demo




https://user-images.githubusercontent.com/58892350/146713978-5a11bbbc-c7bf-40a8-8f0c-dbb9f4a77af2.mp4




## Tech Stack

**Data analysis :** Pandas and Numpy

**Dash boards:** Plotly , Pil

**Front end:** Streamlit and python


## licenses



[![MIT License](https://img.shields.io/apm/l/atomic-design-ui.svg?)](https://github.com/tterb/atomic-design-ui/blob/master/LICENSEs)
[![GPLv3 License](https://img.shields.io/badge/License-GPL%20v3-yellow.svg)](https://opensource.org/licenses/)
[![AGPL License](https://img.shields.io/badge/license-AGPL-blue.svg)](http://www.gnu.org/licenses/agpl-3.0)


## Installation

Installation its simple 
1) First install the requirements

```bash
  pip install -r /path/to/requirements.txt.
```
    



2) Insert your APIs keys 
    

    
## API Section

![App Screenshot](https://i.ibb.co/Jc6rH7S/Capture.png)

And then you are ready to go :) 

## Deploy also on docker


![Docker](https://www.clipartmax.com/png/full/146-1469802_logo-logo-docker.png)



As many APIs have protections agains using the two APIs from the same IP , using a docker can help to not be black listed by the service .


To deploy simple do .

```bash
  sudo docker push levydll/apip:latest
```


## APIs used on the project 

 |Company | Description                |
 | :------- | :------------------------- |
 | `VT` | Provides AV analysis on IP |

|Company | Description                |
 | :------- | :------------------------- |
 | `OTX` | Provide inteligence on IP |

|Company | Description                |
 | :------- | :------------------------- |
 | `PulseDive` | Provide inteligence on IP  |


|Company | Description                |
 | :------- | :------------------------- |
 | `IPQualityScore` | Provide fraud score and if IP is VPN or Proxy |

 |Company | Description                |
 | :------- | :------------------------- |
 | `IPDB` | Provide reports on IPs  |


