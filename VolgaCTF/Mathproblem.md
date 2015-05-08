##Volga CTF 2015 Writeup - Mathproblem:

**Category:** PPC 
**Points:** 300

**Solved by:** [@Fitblip](https://github.com/fitblip)

**Description:**

 `nc mathproblem.2015.volgactf.ru 8888`

---

This was a weird challenge, mostly because it required some brain power when I was already very sleepy (and a bit drunk :smiley_cat:). 

Basically as soon as you connected to the server it would spit out the following:
```
Greetings, neonate! Let us check if you can solve one particular problem!

You're given a set of integer numbers x0,x1,...,xn and y. Using parenthesis '(' and ')' and regular arithmetic operations '*','/','+','-' over integer numbers you need to find a mathematical expression that involves each and every xi and evaluates to y. Sending the correct expression advances you to the next round.

E.g. if the problem says '137 421 700 746 equals 1395' your solution may look like this '(700-421)*(746/137)'.

N.b. Division operation is done according to regular integer division rules, so 746/137 == 5 and (700-421)*(746/137) != (700-421)*746/137.

Round 0. Solve!
568 734 922 989 equals 3213
```

The first thing I tried with this was brute force, since I noticed that there was an exceptionally large timeout before it'd say "too slow!" and disconnect (~30 seconds).

What I built originally was really gross, and basically consisted of generating each permutation of "+-/*()" and the 4 numbers going into eval with a try/except block. It felt very wrong to write, but the name of the game is speed in a CTF.  and more importantly it almost worked! The highest it was able to solve to was 12, and I could've probably just kept it trying until I got lucky, but I also didn't want to 1.) hammer the server and 2.) possibly get disqualified!

My code had ~~one~~ many fatal flaws in it though. It would sometimes find solutions where it stuck 2 of the 4 numbers next to eachother, and the remote side interpreted it as a different number all-together. That would break everything and force me to start from the beginning. 

While tracking that bug down I realized that positioning was important, and could limit my keyspace by a few orders of magnitude, so I did some boolean logic and figured out all potential states with no/one/two parenthesis. 

Once I did that the problems were able to be solved nearly instantly. Iterate on that 30 times, and we were presented with a flag!

```
$ python shoppingishardletsgomath.py

...SNIP...

Round 29. Solve!
387 392 453 690 equals 779

Solving [387 392 453 690] == 779
Found! 387+392+453/690 == 779
Sending payload [387+392+453/690]

That's incredible! You've passed! Here's your flag: {you_count_as_fast_as_a_calculator}
Farewell!
```

```python
import itertools
import socket
import sys

def iterate_and_process(all_the_things):
    for thing in all_the_things:  
        calc = "".join(thing)    
        values = [i for i,x in enumerate(thing) if x.isdigit()]

        solution = 0

        try:
            solution = eval(calc)
            if not type(solution) == int:
                solution = 0
        except:
            pass

        if int(solution) == int(magic):
            print "Found! %s == %s" % (calc, magic)
            print "Sending payload [%s]" % calc
            s.send(calc)
            return True
    return False    

if __name__ == "__main__":
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("mathproblem.2015.volgactf.ru", 8888))
    s.recv(16635)

    while True:
        res = s.recv(16635)
        print res

        try:
            a, b, c, d, _, magic = res.split('\n')[-2].split()
        except:
            break

        print "Solving [%s %s %s %s] == %s" % (a,b,c,d,magic)

        derp = []
        for num_string in itertools.permutations([a,b,c,d]):
            for symbol in itertools.product("*+-/", repeat=3):
                derp.append([num_string[0], symbol[0], num_string[1], symbol[1], num_string[2], symbol[2], num_string[3],])                     # a ? b ? c ? d

                derp.append(["(", num_string[0], symbol[0], num_string[1], ")", symbol[1], "(", num_string[2], symbol[2], num_string[3], ")"])  # (a ? b) ? (c ? d)

                derp.append(["(",num_string[0], symbol[0], num_string[1], symbol[1], num_string[2], ")", symbol[2], num_string[3]])             # (a ? b ? c) ? d
                derp.append([num_string[0], symbol[0], "(", num_string[1], symbol[1], num_string[2], symbol[2], num_string[3], ")"])            # a ? (b ? c ? d)

                derp.append([num_string[0], symbol[0], "(", num_string[1],symbol[1], num_string[2], "(", symbol[2], num_string[3], ")", ")"])   # a ? (b ? (c ? d))
                derp.append([num_string[0], symbol[0], "(", "(", num_string[1], symbol[1], num_string[2], ")", symbol[2], num_string[3], ")"])  # a ? ((b ? c) ? d)

                derp.append(["(", "(",num_string[0], symbol[0], num_string[1], ")", symbol[1], num_string[2], ")", symbol[2], num_string[3]])   # ((a ? b) ? c) ? d
                derp.append(["(", num_string[0], symbol[0], "(", num_string[1], symbol[1], num_string[2], ")", ")", symbol[2], num_string[3]])  # (a ? (b ? c)) ? d
               
                derp.append([num_string[0], symbol[0], num_string[1], symbol[1], "(", num_string[2], symbol[2], num_string[3], ")"])            # a ? b ? (c ? d)
                derp.append(["(", num_string[0], symbol[0], num_string[1], ")", symbol[1], num_string[2], symbol[2], num_string[3]])            # (a ? b) ? c ? d
                derp.append([num_string[0], symbol[0], "(", num_string[1], symbol[1], num_string[2], ")", symbol[2], num_string[3]])            # a ? (b ? c) ? d
                 
        if iterate_and_process(derp):
            continue
        else:
            # We failed :(
            break
```

#####FLAG = {you_count_as_fast_as_a_calculator}
