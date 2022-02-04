# CVE Track
Georgia Tech Cybersecurity Masters Practicum project - Spring 2022.

Ryan Passage, rpassage@gatech.edu 

## Background
My employer is a manufacturer of print devices and provides related software and services for managing enterprise device fleets. Often overlooked by IT departments as a vector for security compromise, printers are increasingly coming under attack by bad actors and greater scrutiny by security professionals who participate in conferences and hack-a-thons.

We are continually evaluating the security of our products and looking for new ways to improve, enhance, and assess our platforms, however we have long needed a more robust system for correlating product vulnerabilities (CVEs) with the firmware or software versions that are affected.

## Problem and Benefit
Today, CVE information is managed using a disjointed mix of spreadsheets, articles and alerts on our website, and plain old institutional knowledge. It is not a scalable or distributed approach and has many single points of failure. As a highly data-driven organization, having a single source of truth for this information would enable new security opportunities for teams to integrate this information into their own projects. Adding this capability to our devices should lead to better proactive outcomes as new threats to our products (and thus our customers’ environments) emerge.

This solution solves two specific problems that the organization and our customers face today:
1. Firmware CVE vulnerability status (historical and current) is not well organized and
cannot be searched, correlated, or integrated with other services.
2. Customer environments are left exposed to new vulnerabilities absent any automatic on-device functionality to check and alert based on new status updates.

In addition to the organizational benefits stated earlier, implementing the second item above is critical to capturing the full benefit of this new system. While we do offer managed print services, many of our customers with large IT departments choose to manage their own print fleets themselves. Some are very proactive with their security updates while others give printer firmware updating low priority. These are the users that would benefit most from an integrated security update check function with administrative alerting. Currently, this capability does not exist in any of our devices or our network-based management tools.

The company would also expect to see a lower volume of technical support requests over time as average firmware version deployed across all customers improves. This benefit may be realized as lower cost and better resource management within the support team.

## Deliverables
The project I propose has two main objectives:
1. Create an internal vulnerability reference database and develop a companion web-based API that can process secure, authenticated queries from various sources. The database would track product versions, associated CVEs and descriptions, links to the company’s support article for remediation, and other useful data points.
2. Design and develop a proof-of-concept app that can be installed on our devices, using a Java-based SDK platform that we call the embedded solutions framework (ESF). This app would enable the device-to-API communications for firmware vulnerability status checks performed on a configurable cadence and then notify device administrators if new threats are found.

## Challenges, Outcome, and Evaluation
Challenges to successfully completing this project vary, but I have identified the following primary concerns:
1. Successful assimilation of various version number schemes and applying business logic to determine CVE relevance. Addressed by consulting with internal firmware subject matter experts.
2. Overcoming my own knowledge gaps related to embedded framework application development to successfully create the PoC app. Addressed by reading SDK and example application code provided; discussions with internal ESF developers for support.

Successful completion of this project will accomplish delivery of the two main deliverables: CVE reference database with secure API and a working proof-of-concept embedded device application. The knowledge gained by designing and implementing this project will be shared with internal parties to gauge interest in adopting the system design and functionality.

While there is no obligation on my employer’s part to adopt this system, I have seen a high level of interest in both helping me achieve my goals and then realizing potential benefits from this work back to the company. This is a trailing metric that can reflect overall project success.

## Tools and Platforms
I will be employing a set of modern tools to ensure this system can perform as expected.
* Development will be done using Python for the database admin and API, and Java for
the embedded device app. GitHub will be used to manage code repositories.
* Data will be hosted on Microsoft Azure using Azure SQL and containerized Azure web
functions to process the API traffic.
* Security will be provided by Microsoft authentication services (multi-factor), API tokens,
and HTTPS connectivity.

By utilizing “batteries included” modules such as Django for Python as well as cloud resources and Azure’s nimble developer-oriented services, the system should be responsive and highly available.
