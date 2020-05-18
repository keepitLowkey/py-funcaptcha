# py-funcaptcha
Python module for interacting with ArkoseLabs' FunCaptcha

### Usage
```python
from py_funcaptcha import FunCaptchaSession

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
    ## Submit guess
    solved = submit(51.4)

## Print final result
print("Solved ::", solved)
```
