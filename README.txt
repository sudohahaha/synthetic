Sythetic trace generation process:

variables explainations is in: ./generate.sh -h

1. assume the $gap is 50, and $m (upper bound of heavy hitter, see more at the 3rd process) is 1000

2. the group will be split into:[[0 50], [51 100], ... , [951 1000]], the portion of flows will be distributed in each interval according to power law distribution

3. power law parameters: f = c * x^k, where c is set to 1 but would vary along with other paramenters, k is the exponent and is the only parameters has to be set up.

4. the lower bound of heavy hitter provides a reference for the program to stop after the generate enought packtes which fit into the corresponding power law function.

5. by default, plots would be shown at the terminal for the group distribution, set -s with any arguments will block these plots, useful when expected a large flow number
------------------------------------------------
		example
------------------------------------------------
./generate -f 200 -p 2000 -m 1000 -g 50 -e 1.7 

* this would be generate 200 flows with minimal size 2000. 
* group: [[0 50],[51 100], ..., [150 200]]. 
* the maximum size of flow would be around 1000, and the portion of the flows in each interval would be calculated from the given power law function

------------------------------------------------
		example
------------------------------------------------
./generate -f 200 -p 2000 -m 1000 -g 50 -e 1.7 -a syn_flood

* extra parameter -a would include a attack pattern, here is syn_flood attack
* if you want DIY the paramerts, set -d and the terminal will ask for the input


