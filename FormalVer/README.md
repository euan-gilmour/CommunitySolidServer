
# VC-Based Third Party Authentication Protocol

The VC-based protocol is divided into two different parts: The issuance of the VC by the issuer and its use to access private resources in a pod. Both parts are divided by a fictive sovereignty line, depicting the breaking point at which the issuer loses sight of the users targeted pod, thus increasing their privacy. The handshake used in the model can be found [here](/sts).

![MSC of ...](/msc/msc_vc_based.png)

# Results

| Property  | Holds | Note |
| ------------- | ------------- | ------------- |
| Finish Issuer | Yes  | The issuer finishes the protocol. |
| Finish User to Issuer | Yes  | The user finishes talking to the issuer. |
| Finish User to Pod | Yes  | The user finishes talking to the pod. |
| Finish Pod | Yes  | The pod finishes the protocol. |
| Secret K_IU | Yes  | The established communication key K_IU between issuer and user remains secret. |
| Secret K_UP | Yes  | The established communication key K_UP between user and pod remains secret. |
| Authentication Issuer  | Yes  | The issuer is able to authenticate the user. |
| Authentication User  | Yes  | The user is able to authenticate the issuer. |
| Authentication User-All  | Yes  | The user authenticates non-injectively the issuer and pod.(1) |
| Authentication Pod  | Yes  | The pod is able to authenticate the user. |

Property (1) is working as expected as the same PT may be used multiple times in multiple sessions.
