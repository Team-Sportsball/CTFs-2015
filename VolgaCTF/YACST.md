##Volga CTF 2015 Writeup - YACST:

**Category:** PPC & Recon 
**Points:** 200

**Description:**

 Try to solve another captcha - [server](http://yacst.2015.volgactf.ru/)

---

This challenge was interesting, and gave me a glimpse into how /awful/ the speech recognition engines out there truely are. [PocketSphinx](https://github.com/cmusphinx/pocketsphinx-python), [SpeechRecognition](https://pypi.python.org/pypi/SpeechRecognition/), and everything else I tried were extremely painful to install, annoying to use, and required very specific PCM formats (which of course these were *not* in).

For brevity's sake I started exploring other possible solutions, and after looking around the binary I noticed there was very little noise between each word. At the same time I decided to google around for `Copyright (c) 2015 Anny Carter - github` since it seemed odd to be on the page. I stumbled across a Gist (which has since been deleted, but still cached by google - [https://gist.github.com/annycarter/c3ea777e7a820cd296a2](http://webcache.googleusercontent.com/search?q=cache:-sRRQO7RXxoJ:https://gist.github.com/annycarter+&cd=1&hl=en&ct=clnk&gl=us)) which had the startup script for her captcha solution located at [http://yacst.2015.volgactf.ru/samples/](http://yacst.2015.volgactf.ru/samples/), which contains a clean copy of every number.

Enter fuzzy hashing.

After downloading all of the samples into a directory along with a test sample `captcha.wav`, and trimming off the noise (basically just `rstrip`/`lstrip` for `\x00`), I used the [ssdeep](https://pypi.python.org/pypi/ssdeep) module to generate a fuzzy hash of each number, and made sure that the test sample was able to be parsed properly.

From there it was a simple matter of taking in the WAV file, dividing it by 6 (even though the file sizes for each sample differed, it was good enough), and comparing each parsed number with the fuzzy hashes I already had. If it matched with 75% certianty it was probably a match. It solved each captcha extremely quickly and had 5 solved in no time (and was a LOT easier than configuring Sphinx ;)).

```python
import ssdeep
import sys
import requests

with open('captcha.wav', 'rb+') as f:
    captcha = f.read()

hashes = {}

# Read in all samples and fuzzy hash them.
for x in xrange(0,10):
    with open("%s.wav" % x, 'rb+') as f:
        hashes[x] = ssdeep.hash(f.read()[60:].lstrip('\xff').rstrip('\xff'))

def chunks(l, n):
    """ Yield successive n-sized chunks from l.
    """
    for i in xrange(0, len(l), n):
        yield l[i:i+n]

def crack(captcha):
    num = ""
    # For each slice
    for index, audio_chunk in enumerate([x for x in chunks(captcha, len(captcha) / 6)]):
        # Hash the trimmed slice
        chunk_hash = ssdeep.hash(audio_chunk.lstrip('\xff').rstrip('\xff'))
        for number, audio_hash in hashes.iteritems():
            # If we have a 75% or higher certainty, go with it. 
            if ssdeep.compare(chunk_hash, audio_hash) > 75:
                num += str(number)
                break
    return num

s = requests.session()
captcha_url = 'http://yacst.2015.volgactf.ru/captcha'
for x in range(5):
    captcha_audio_stream = s.get(captcha_url).content
    cracked_captcha = crack(captcha_audio_stream)
    res = s.post(captcha_url, data={"captcha": cracked_captcha})
print res.content
```

#####FLAG = {W3N33DMORE3nTR0Py}
