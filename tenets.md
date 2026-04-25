# Service & Checker Tenets

## Service

### General
- [ ] A service MUST be able to store and load flags for a specified number of rounds
- [ ] A service MUST NOT lose flags if it is restarted
  - data (sqlite-db) mapped outside docker container
- [ ] A service MUST be rebuilt as fast as possible, no redundant build stages should be executed every time the service is built
  - initial start may take a minute, but that is okay
- [ ] A service MUST be able to endure the expected load
  - service does only RSA ENcryption with `e = 17`, and sqlite queries
- [ ] A service SHOULD NOT be a simple wrapper for a key-value database, and SHOULD expose more complex functionality
  - way too trivial
- [ ] Rewriting a service with the same feature set SHOULD NOT be feasible within the timeframe of the contest
  - easily done
- [ ] A service MAY be written in unexpected languages or using fun frameworks
  - simple python, aiosqlite may be unknown, but does nothing weird

### Vulnerabilities
- [ ] A vulnerability MUST be exploitable and result in a correct flag
- [ ] A vulnerability MUST stay exploitable over the course of the complete game (I.e. auto delete old flags, if necessary) 
  - no autodelete, yet, but easily included
- [ ] A service SHOULD have more than one vulnerability
- [ ] A service MUST have at least one complex vulnerability
  - both vulns are easy
- [ ] Vulnerabilities SHOULD NOT be easily replayable 
  - partially, sqli replayable, crypto exploit does not show in traffic
- [ ] Every vulnerability MUST be fixable with reasonable effort and without breaking the checker
- [ ] A service SHOULD NOT have unintended vulnerabilities
- [ ] A service SHOULD NOT have vulnerabilities that allow the deletion but not the retrieval of flags
- [ ] A service SHOULD NOT have vulnerabilities that allow only one attacker to extract a flag
- [ ] A vulnerability MUST be exploitable without renting excessive computing resources
  - taking 17th root is fast
- [ ] A vulnerability MUST be expoitable with reasonable amounts of network traffic
  - exploit by single request
- [ ] A service MUST have at least one "location" where flags are stored (called flag store)
- [ ] A service MAY have additional flag stores, which requires a separate exploit to extract flags
  - both vulns lead to same flag store

## Checker
- [ ] A checker MUST check whether a flag is retrievable, and MUST NOT fail if the flag is retrievable, and MUST fail if the flag is not retrievable
- [ ] A checker MUST NOT rely on information stored in the service in rounds before the flag was inserted
- [ ] A checker MAY use information stored in previous rounds, if it gracefully handles the unexpected absence of that information
- [ ] A checker MUST NOT crash or return unexpected results under any circumstances
- [ ] A checker MUST log sufficiently detailed information that operators can handle complaints from participants
  - `self.debug` writes some logs
- [ ] A checker MUST check the entire functionality of the service and report faulty behavior, even unrelated to the vulnerabilities
  - though more by accident, since there is no further functionality
- [ ] A checker SHOULD not be easily identified by the examination of network traffic
  - storing information can only come from the checker
  - but more important: `getflag` indistinguishable from crypto exploit
- [ ] A checker SHOULD use unusual, incorrect or pseudomalicious input to detect network filters
