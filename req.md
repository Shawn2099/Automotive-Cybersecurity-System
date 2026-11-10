
Existing System
Manufacturer-installed telematics systems collect vehicle data through onboard communication interfaces.

Data such as vehicle speed, GPS location, and driving behaviour may be transmitted to manufacturer servers.

Users can monitor vehicle information through company-specific mobile applications.

Systems may support both read and write operations, depending on their architecture and permissions.

Cloud connectivity often depends on cellular networks and may involve subscription or renewal costs.



Pros and Cons of Existing System
Pros

Installed and supported by vehicle manufacturers.

Dedicated mobile applications for vehicle monitoring.

Remote access to vehicle information through cloud connectivity.

Cons

Vehicle data may be accessible to manufacturers, depending on their data policies.

Continuous cloud connectivity may require a SIM or cellular subscription.

Manufacturer-specific systems may have limited compatibility with other vehicles.

Remote write capabilities, if insufficiently secured, can introduce cybersecurity risks.



Advantages Over Existing System

Privacy-focused: Vehicle data is processed locally without requiring routine transmission to manufacturer servers.

Retrofittable design: Intended to support compatible CAN-equipped vehicles through a plug-and-play installation, subject to vehicle compatibility.

Offline operation: Core monitoring and AI analysis can work on the edge device without internet access.

Intelligent monitoring: Combines component health scoring, fault detection, predictive analytics, and cybersecurity risk assessment.

Flexible connectivity: Optional encrypted cloud communication and read-only operation reduce unnecessary remote access and potential attack surfaces.



Proposed System

An ESP32-based interface collects vehicle data through the OBD-II/CAN port and forwards it to an edge device such as a Raspberry Pi or NVIDIA Jetson.

Python-based AI models analyse vehicle health, detect faults, forecast potential issues, and check sensor consistency.

Each vehicle component receives a health score, which contributes to an overall vehicle health score out of 100.

Cybersecurity analytics identify suspicious CAN communication and assign risk scores to detected anomalies.

An optional encrypted cloud connection enables secure data transfer, while local processing and voice alerts help minimise driver distraction.



Conclusion

 Integrates AI-based vehicle health monitoring and cybersecurity.

Enables real-time fault detection and predictive maintenance.

 Ensures privacy-focused, offline-capable edge processing

 Provides a secure, flexible, and cost-effective vehicle monitoring solution.



Also if needed 1 more feature add chyam more than 1 car (any brand per user) add chyam

Like if I have a maruti car and a Toyota car , same appil ellam kannam
no need for 2
