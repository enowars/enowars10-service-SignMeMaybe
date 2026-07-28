# Service & Checker Tenets

Note: X means fullfilled; ~ means partially fullfilled; [] means not fullfilled.

## Service

### General
- [~] A service MUST be able to store and load flags for a specified number of rounds
  - Unsure: was able to store and load flags for some time but at some point the service got too unstable unfortunately.
- [X] A service MUST NOT lose flags if it is restarted
  - data (sqlite-db) mapped outside docker container
- [X] A service MUST be rebuilt as fast as possible, no redundant build stages should be executed every time the service is built
- [~] A service MUST be able to endure the expected load
  - Unsure: the service was able to endure the load on the perma and during enowars10 for some time but at some point the service got too unstable unfortunately.
- [X] A service SHOULD NOT be a simple wrapper for a key-value database, and SHOULD expose more complex functionality
- [X] Rewriting a service with the same feature set SHOULD NOT be feasible within the timeframe of the contest
- [ ] A service MAY be written in unexpected languages or using fun frameworks

### Vulnerabilities
- [X] A vulnerability MUST be exploitable and result in a correct flag
- [~] A vulnerability MUST stay exploitable over the course of the complete game (I.e. auto delete old flags, if necessary)
  - Unsure: cleanup exists, but as said above. Service got too unstable after some time.
- [X] A service SHOULD have more than one vulnerability
- [X] A service MUST have at least one complex vulnerability
- [X] Vulnerabilities SHOULD NOT be easily replayable 
- [X] Every vulnerability MUST be fixable with reasonable effort and without breaking the checker
- [X] A service SHOULD NOT have unintended vulnerabilities
- [X] A service SHOULD NOT have vulnerabilities that allow the deletion but not the retrieval of flags
- [X] A service SHOULD NOT have vulnerabilities that allow only one attacker to extract a flag
- [X] A vulnerability MUST be exploitable without renting excessive computing resources
- [X] A vulnerability MUST be expoitable with reasonable amounts of network traffic
- [X] A service MUST have at least one "location" where flags are stored (called flag store)
- [X] A service MAY have additional flag stores, which requires a separate exploit to extract flags

## Checker
- [X] A checker MUST check whether a flag is retrievable, and MUST NOT fail if the flag is retrievable, and MUST fail if the flag is not retrievable
- [X] A checker MUST NOT rely on information stored in the service in rounds before the flag was inserted
- [X] A checker MAY use information stored in previous rounds, if it gracefully handles the unexpected absence of that information
- [ ] A checker MUST NOT crash or return unexpected results under any circumstances
  - Note: During perma stup before enowars and during enowars the service was crashing and restarting. Unfortunately I was not able to find a reliable fix anymore.
- [X] A checker MUST log sufficiently detailed information that operators can handle complaints from participants
  - Debug logging is present around service calls and validation steps.
- [X] A checker MUST check the entire functionality of the service and report faulty behavior, even unrelated to the vulnerabilities
- [X] A checker SHOULD not be easily identified by the examination of network traffic
- [X] A checker SHOULD use unusual, incorrect or pseudomalicious input to detect network filters
