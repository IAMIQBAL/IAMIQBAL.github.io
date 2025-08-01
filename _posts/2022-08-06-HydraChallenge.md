---
title: The Hydra Corp | Arab CyberSecurity WarGames CTF
author:
  name: iamiqbal
  link: https://twitter.com/0xiqb4l
date: 2022-08-06 5:00:00
categories: [ACSWG, OSINT]
tags: [OSINT, exiftool]
---

This is the writeup for Hydra Corp Challenge of Arab CyberSecurity Wargames CTF. It was a 900 pts challenge.

# **Challenge Description**
___

> The world has become an unsafe place and has become full of evildoers. Terrorist operations have become a big business that many extremist groups from all races, religions, and countries use. Indeed, some countries have taken extremism and violence as a method for them to impose their control over the surrounding area.During the investigation, the FBI office found a communication map between a group of extremist elements belonging to different groups.After a careful investigation, the analysts of the FBI found that there were two people in the same group who were sending some dangerous classified information to each other.If you can find these two like the Bureau did and find out what secrets they convey, you will find your science.

# **Challenge Files**
___
We are given an image of Learner Driving License of the subject.

![LD](/assets/img/ACSWG/photo_2022-05-14_03-37-41.jpg)
<br>

# **Hint**
> Section 5 is important

# **Solution**

## **Section 5**

Based on the hint, when we inspect the section 5 of the license, we can see that it is kind of a serial number. But some letters are invisible due to the reflection. But the same serial number is given below. 

I first typed this serial number in Google search bar and it came up with few images of driving licenses. This is the point when I noted that we are given a license that has its photo replaced with a fake one and the read license has letter **L** but ours had a barcode.

![Section 5](/assets/img/ACSWG/1.png)

## **The BAR Code**

What are we supposed to do with the barcode? Google Lens for the rescue. I opened google lens in my phone and zoomed in the license that was given in the challenge and scanned the **Bar code**. 

![Bar Code](/assets/img/ACSWG/2.png)

## **The Matrix**

When we tap on the link, we are redirected to a map with several markers of people having connections with militants groups. The challenge description says there are two people sending classified information so we know that we have to find **two markers** in the map. I kept tapping on every marker until I found two with pastebin links.

![Culprit 1](/assets/img/ACSWG/3.png)
![Culprit 2](/assets/img/ACSWG/4.png)

## **The Pastebin Links**

On visiting both links, we find that these pastebins contain some kind of base64 encoded strings. 

Note: One of the pastebin is locked, its password is already given, which is the license number.

## **The Mysterious Base64 String**

The given ciphers look like base64 strings but are actually RSA Key and Msg. We paste these key and cipher msg in an online decoder aaaaannnnnDDD!

![RSA](/assets/img/ACSWG/5.png)

We Finally have a link.

https://postimg.cc/gallery/WvQpm6X

## **The Last Duel**

When we visit the link, It contains 5 images of different guns, bombs, and warfare vehicles.

![WAR](/assets/img/ACSWG/6.png)

We download these images and see the metadata of images using **exiftool**.

```bash
┌──(kali㉿kali)-[~/Downloads]
└─$ exiftool [filename]
```

And the exifdata of grenades-large.jpg contains the flag.

![FLAG](/assets/img/ACSWG/7.png)

## **The FLAG**

```ACSWG{M@kE_Th3_WOr1D_5@fEr}```