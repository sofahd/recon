# SOFAH Reconnaissance Service (Recon)

The Reconnaissance Service (`recon`) is a specialized component of the SOFAH (Speedy Open Framework for Automated Honeypot-development) framework, tasked with performing initial data gathering and analysis on potential attack vectors. By simulating network environments and analyzing incoming traffic, `recon` aids in dynamically configuring honeypots to mirror real-world systems more accurately.

## Overview

`recon`'s primary objective is to collect detailed information about the network environment and potential attacker techniques. This data informs the dynamic configuration of the honeypot, enabling it to emulate services, ports, and vulnerabilities that are most likely to be targeted by attackers. This proactive approach enhances the honeypot's effectiveness and realism.

## Key Features

- **Port Scanning**: Identifies open ports on the target system to simulate in the honeypot.
- **Service Identification**: Determines the services running behind open ports to tailor the honeypot's responses.
- **Integration with ENNORM**: Seamlessly works with the ENrichment NORMalization (ENNORM) module to apply gathered data towards service configuration.
