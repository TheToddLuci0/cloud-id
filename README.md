# Cloud ID

Check what cloud service providers your target is using.
Provide a list of IPs, get a list of services and providers they use.

## Useage
`python3 cloud-id.py target_ips.txt`

## Technical
Okay, so this thing is optimized using the `vibes` method.

Currently, we search addresses one at a time, in the order AWS ->  Azure -> GCP.
This is based entirely on my vibe that that's the most likely order.
Ideally, we'd thread out, and have some mechanism for removing from all ques once 
once of the providers finds a match, but.... that's hard.

We're also fetching the list of addresses for each provider on each invocation.
We should probably vendor those and update at some interval, but that's hard.


### TODO
- [ ] Optimize
    - [ ] Multithread
- [ ] Make `pip install`-able
- [ ] Add more providers
    - [ ] Akami
    - [x] Fastly
    - [x] Cloudflare
    - [ ] Everyone else