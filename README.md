# py-funcaptcha
Python module for interacting with ArkoseLabs' FunCaptcha

### Things to note
- `<ch>.full_token` is the token you submit to the website once you solved the challenge
- ArkoseLabs may enable the verification of IP addresses on your target website at any given time, thus requiring you to submit the token from the same IP address you solved it from


### Setup
```bash
sudo apt install nodejs
pip3 install -r requirements.txt
```


### Usage
```python
from py_funcaptcha import FunCaptchaSession
from random import randint

## Create session for Roblox's login endpoint
s = FunCaptchaSession(
    public_key="9F35E182-C93C-EBCC-A31D-CF8ED317B996",
    service_url="https://roblox-api.arkoselabs.com",
    page_url="https://www.roblox.com/login",
    proxy="https://127.0.0.1:8888")
## Obtain challenge
ch = s.new_challenge()

## Print challenge details
print("Full Token ::", ch.full_token)
print("Session Token ::", ch.session_token)
print("Challenge Token ::", ch.token)
print("# of Images ::", len(ch.image_urls))

## Iterate over challenge images
for image, submit in ch.get_iter():
    ## Display image using PIL's image.show() method
    image.show()
    ## Generate random guess
    guess = ch.angle * randint(1, 360/ch.angle)
    ## Submit guess
    solved = submit(guess)

## Print final result
print("Solved ::", solved)
```
