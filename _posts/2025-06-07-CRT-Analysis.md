---
layout: post
title: "CRT Analysis"
date: 2025-06-07 00:00:00 +0000
category : [Reverse, OALAB]
tags: reverse, malware-analysis
---

# stage 2 x32 extracted   

## Import / Export

### Import 

In import section we get a lot of dll and function so there is probably no dynamic dll resolution :

![ida15](/assets/images/DLL/ida15.png)

### Export

![ida16](/assets/images/DLL/ida16.png)

As we get only start as main entry in export we can deduce we're dealing with an `exe` file.

## Entry point

![ida17](/assets/images/DLL/ida17.png)

Our entry point is the start function, with the `security init cookie` and `c runtime start`.

![ida18](/assets/images/DLL/ida18.png)

Ida print in red some memory value which is located in the pe header and is not loaded by default by ida.

![ida19](/assets/images/DLL/ida19.png)

To fix those "errors" we can start from scratch, open and load manually the exe by selecting yes with default value (and loading header) and finally clicking yes on warning. 

![ida20](/assets/images/DLL/ida20.png)


