rule APT32_KerrDown: apt apt32 winmalware downloader
{
    meta:
        Author = "Adam M. Swanda"
        Website = "https://www.deadbits.org"
        Repo = "https://github.com/deadbits/yara-rules"
        Date = "2019-08-08"
        Note = "List of samples used to create rule at end of file as block comment"

    strings:
        $hijack = "DllHijack.dll" ascii fullword
        $fmain = "FMain" ascii fullword
        $gfids = ".gfids" ascii fullword
        $sec01 = ".xdata$x" ascii fullword
        $sec02 = ".rdata$zzzdbg" ascii fullword
        $sec03 = ".rdata$sxdata" ascii fullword

        $str01 = "wdCommandDispatch" ascii fullword
        $str02 = "TerminateProcess" ascii fullword
        $str03 = "IsProcessorFeaturePresent" ascii fullword
        $str04 = "IsDebuggerPresent" ascii fullword
        $str05 = "SetUnhandledExceptionFilter" ascii fullword
        $str06 = "QueryPerformanceCounter" ascii fullword

condition:
        (uint16(0) == 0x5a4d)
        and
        (
            ($hijack and $fmain and $gfids)
            or
            ($gfids and 6 of them)
        )
}

/*
    Matched sample set:

        4a0309d8043e8acd7cb5c7cfca95223afe9c15a1c34578643b49ded4b786506b
        4b431af677041dae3c988fcc901ac8ec6e74c6e1467787bf099c4abd658be5be
        4bc00f7d638e042da764e8648c03c0db46700599dd4f08d117e3e9e8b538519b
        4e2f8f104e6cd07508c5b7d49737a1db5eeba910adfdb4c19442a7699dc78cfc
        4e791f2511c9bd3c63c8e37aa6625d8b590054de9e1cca13a7be2630bc2af9ce
        539e8a53db3f858914cfe0d2132f11de34a691391ba71673a8b1e61367a963c7
        53cd92f37ffd0822cc644717363ba239d75c6d9af0fa305339eaf34077edd22d
        53efaac9244c24fab58216a907783748d48cb32dbdc2f1f6fb672bd49f12be4c
        5c18c3e6f7ac0d0ac2b5fa9a6435ee90d6bd77995f85bed9e948097891d42ca2
        5f0db8216314da1f128b883b918e5ac722202a2ae0c4d0bf1c5da5914a66778e
        6010d44cdca58cdec4559040e08798e7b28b9434bda940da0a670c93c84e33cd
        60b65ebb921dca4762aef427181775d10bbffc30617d777102762ab7913a5aa1
        6146aedfe47597606fb4b05458ec4b99d4e1042da7dc974fa33a57e282cd7349
        6245b74b1cc830ed95cb630192c704da66600b90a331d9e6db70210acb6c7dfa
        67cd191eb2322bf8b0f04a63a9e7cb7bc52fb4a4444fcb8fed2963884aede3aa
        68f77119eae5e9d2404376f2d87e71e4ab554c026e362c57313e5881005ae79e
        69e679daaaff3832c39671bf2b813b5530a70fb763d381f9a6e22e3bc493c8a9
        6fb397e90f72783adec279434fe805c732ddb7d1d6aa72f19e91a1bf585e1ea5
        70db041fb5aadb63c1b8ae57ba2699baa0086e9b011219dcebcccbf632017992
        7673f5468ba3cf01500f6bb6a19ce7208c8b6fc24f1a3a388eca491bc25cd9cd
        77805a46f73e118ae2428f8c22ba28f79f7c60aeb6305d41c0bf3ebb9ce70f94
        788265447391189ffc1956ebfec990dc051b56f506402d43cd1d4de96709c082
        7be613237b57fbc3cb83d001efadeed9936a2f519c514ab80de8285bdc5a666c
        7dbb7fab4782f5e3b0c416c05114f2a51f12643805d5f3d0cd80d32272f2731a
        7ec77e643d8d7cc18cc67c123feceed91d10db1cc9fa0c49164cba35bb1da987
        860f165c2240f2a83eb30c412755e5a025e25961ce4633683f5bc22f6a24ddb6
        89759e56d5c23085e47d2be2ce4ad4484dfdd4204044a78671ed434cec19b693
        8b7fb1cd5c09f7ec57ccc0c4261c0b4df0604962556a1d401b9cbfd750df60ba
        8d6e31c95d649c08cdc2f82085298173d03c03afe02f0dacb66dd3560149184f
        942d763604d0aefdff10ce095f806195f351124a8433c96f5590d89d809a562f
        98a5f30699564e6d9f74e737a611246262907b9e91b90348f7de53eb4cf32665
        9e6011d6380207e2bf5105cde3d48e412db565b92cdc1b3c6aa15bd7bd4b099f
        a106e0a6b7cc30b161e5ea0b1ec0f28ab89c2e1eb7ba2d5d409ddbabc3b037e6
        a2b905c26e2b92e63de85d83e280249258cb21f300d8c4a3a6bdb488676e9bcf
        a4a86e96f95f395fcf0ceb6a74a2564f4ba7adbe1b40cc702b054427327a0399
        a8192656dd1db0be4cec9d03b4d10e0529d9c52c899eda8d8e72698acfb61419
        a8f776bd3a9593e963b567ce790033fec2804ea0afb40a92d40e21d8f33d066f
        b4966f8febdba6b2d674afffc65b1df11e7565acbd4517f1e5b9b36a8c6a16ed
        bb25f1a73d095d57b2c8c9ac6780e4d412ddf3d9eef84a54903cc8e4eaefc335
        bc82bce004afb6424e9d9f9fc04a84f58edf859c4029eda08f7309dbeec67696
        c30198e0b0e470d4ac8821bd14bb754466e7974f1c20be8b300961e9e89ed1ea
        caabc45e59820a4349db13f337063eddede8a0847ae313d89a800f241d8556c8
        d3ef6643ad529d43a7ec313b52c8396dc52c4daad688360eb207ee91a1caf7b2
        e3c818052237bb4bb061290ab5e2a55c3852c8a3fef16436b1197e8b17de2e18
        e56ffcf5df2afd6b151c24ddfe7cd450f9208f59b5731991b926af0dce24285a
        e8704bf6525c90e0f5664f400c3bf8ff5da565080a52126e0e6a62869157dfe3
        e8a454cd8b57a243f0abeec6945c9b10616cfdcc4abfb4c618bfc469d026d537
        eac776c3c83c9db1a770ffaf6df9e94611c8293cbd41cb9257148603b8f2be0b
        ead0f3e6f0ca16b283f09526d09e8e8cba687dab642f0e102e5487cb565bf475
        f011a136996fa53fdbde944da0908da446b9532307a35c44ed08241b5e602cc9
        f2a2f4fa2ed5b2a94720a4661937da97ab21aa198a5f8c83bb6895aa2c398d22
        f62f21ee7e642f272b881827b45ceb643c999a742e1d3eac13d1ba014d1e7f67
        f9f0973dc74716b75291f5a9b2d59b08500882563011d1def2b8d0b1b9bbb8ae
*/
