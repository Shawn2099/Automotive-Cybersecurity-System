# Screenshot list (PoC web UI)

| File | Caption draft | State shown |
|---|---|---|
| ui_controller.jpg | Car controller simulator driving the bench car in city mode. | Car Controller at localhost:8100, "city" preset applied (speed 40 km/h, throttle 25%, live reported state). No faults or attacks enabled. |
| ui_dashboard_normal.jpg | Monitoring dashboard during normal driving. | Dashboard at localhost:8001, Bench Car (ESP32) selected and Live. Speed 67 km/h, overall health 100, cyber risk 0, attack class Normal. |
| ui_dashboard_overheat.jpg | Dashboard response to an engine overheating fault. | Fault "overheat" enabled for about 25 s. Coolant 128 C, overall health 53, thermal subsystem at 25, MIL lamp on, HIGH MECHANICAL alerts in the feed. Fault then disabled. Scrolled view so the alert feed is visible. |
| ui_dashboard_dos.jpg | Dashboard detecting a CAN DoS flood. | CAN attack "dos" active. Cyber risk 95, attack class "DoS flood (100%)", CRITICAL CYBER alerts with about 5,400 frames/s. Attack then disabled. |
| ui_crop_cyber_panel.png | Cyber-risk panel and alert feed during a DoS flood. | Close-up of the cyber-risk gauge, attack class label, and CRITICAL CAN flood alerts from the DoS run. |
| ui_dashboard_rpm_spoof.jpg | Dashboard detecting forged RPM messages. | CAN attack "rpm_spoof" active. Cyber risk 85, attack class "Spoofing (100%)". Attack then disabled. Note: the displayed RPM did not visibly reach the forged 6500 value in this capture. |
| ui_dashboard_tamper.jpg | Dashboard during a tunnel tampering attack. | Tunnel attack "tamper" active. Cyber risk 80, attack class "Tunnel attack (95%)". Encryption inspector shows the rejected counter rising (101 at capture time). Attack then disabled. |
| ui_crop_encryption_inspector.png | Encryption inspector rejecting tampered tunnel packets. | Close-up of the encryption inspector during the tamper run: accepted count, rejected count (156), AES-128-GCM ciphertext hex, and decrypted JSON batch. |
| ui_add_car.png | Provisioning a new vehicle in the portal. | Add Car dialog after registration of "Paper Demo Car" (Toyota Corolla, DEMO-02). Device ID and ingest URL shown; PSK replaced with "•••• (redacted)" before capture. Profile "Not supported yet". |
| ui_vehicle_list.png | Vehicle list with mixed registration states. | Car cards: Bench Car (ESP32) status Live with health and cyber values; Test Swift and Paper Demo Car status Awaiting device. |

Notes
- Files are JPEG (ui_*.jpg) or PNG (ui_crop_*, ui_add_car, ui_vehicle_list) as returned by the browser capture tool; convert with an image tool if the venue requires PNG for every figure.
- All attacks and faults were disabled at the end; the controller's FAULTS and CAN ATTACKS checkboxes were verified unchecked.
- The PSK is redacted in ui_add_car.png. The Paper Demo Car is now registered in the portal and remains in the database.
