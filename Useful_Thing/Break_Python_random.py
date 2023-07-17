#https://github.com/kmyk/mersenne-twister-predictor

import random
from mt19937predictor import MT19937Predictor

predictor = MT19937Predictor()
for _ in range(624):
    x = random.getrandbits(32) 
    predictor.setrandbits(x, 32)

assert random.getrandbits(32) == predictor.getrandbits(32)
