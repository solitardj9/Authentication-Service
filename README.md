# Authentication-Service

## 1. Create an Internal CA Certificate
> 1) create a Key Pair (Public Key, Private Key)
> 2) create a private certificate

## 2. Register an External CA Certificate
> 1) register a custom Key Pair (Public Key, Private Key)
> 2) register a custom certificate
<pre>
<code>
    HttpMethod : POST
    Path : http://{ip}:{[port}/ca
    {
        "caCert" : "{PEM String}",
        "pvKey" : "{PEM String}"
    }
</code>
</pre>


## 3. Issue a certificate
> 1) submit the csr(certificate signing request) request to generate a certificate
<pre>
<code>
    HttpMethod : POST
    Path : http://{ip}:{[port}/certificate
    {
        "csr" : "{PEM String}"
    }
</code>
</pre>
