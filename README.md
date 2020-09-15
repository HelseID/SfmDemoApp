# Creating user sessions in the SFM GUI using HelseID Access Tokens from EPJ

This repository contains a simple demo that shows how SFM could pass access tokens and handle user logon without exposing the tokens to the web browser. 

The demo consists of two applications:
1. *SfmEpj* - This is a command line application that attempts to simulate the EPJ. It retrieves an acccess token from HelseID and passes it to the SFM api. The application the generates a url that should be used to logon the user and opens the system browser.
2. *SfmPoc* - This is a proof of concept web application that shows how one could setup a backend api and a corresponding front end application. The API implements the protocol as suggested and the front end is only secured using a cookie. The access token is never exposed to the front end application.




