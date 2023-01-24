#When we need to solve a discrete log problem and can fix the prime, a smooth prime will be a better choice

from Crypto.Util.number import isPrime

def smooth_prime(size):
    i = 2
    smooth_p = 1
    while smooth_p < size or not isPrime(smooth_p + 1):
        smooth_p *= i
        i += 1
    smooth_p += 1
    return smooth_p
  
