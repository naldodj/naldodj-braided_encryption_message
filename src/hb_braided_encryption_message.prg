/*
    "Harbour braided key offset encryption" (criptografia por deslocamento de chave trançada).
    Released to Public Domain.
*/

/* Keeping it tidy */
#pragma -w3
#pragma -es2

/* Optimizations */
#pragma -km+
#pragma -ko+

function EncryptMessage(cMessage as character, /*@*/cKey)

    local cEncrypted as character

    local i,nLen as numeric

    nLen:=Len(cMessage)

    if (empty(cKey))
        cKey:=GenPwd(nLen+hb_RandomInt(Int(Seconds()))%15,"QqWwEeRr456_TtYyUuIi#OoPpAaSs123-DdFfGgHhJj#KkL_Zz7890XxC-cVvBbNnMm!@#$%^&*()_+[]{}|;:,.<>?/~`0123456789")
    endif

    cEncrypted:=""

    for i := 1 to nLen
        // We obtain the ASCII code of the character and adjust it based on the braiding pattern.
        cEncrypted+=Chr(Asc(SubStr(cMessage,i,1))+GetBraidOffset(cKey,i))
    next i

    return(cEncrypted) as character

function DecryptMessage(cEncrypted as character,cKey as character)

    local cDecrypted as character

    local i,nLen as numeric

    nLen:=Len(cEncrypted)
    cDecrypted := ""

    for i := 1 to nLen
        // Reverts the adjustment made by the braiding.
        cDecrypted+=Chr(Asc(Substr(cEncrypted,i,1))-GetBraidOffset(cKey,i))
    next i

    return(cDecrypted) as character

static function GetBraidOffset(cKey as character, nIndex as numeric)

    local cBraid as character

    local nKeyLen,nBraid,nMod as numeric

    nKeyLen:=Len(cKey)

    //Here I obtain the character according to the index.
    cBraid:=SubStr(cKey,((nIndex-1)%nKeyLen)+1,1)
    //Here I obtain the corresponding ASCII index.
    nBraid:=Asc(cBraid)

    nMod:=Int(Mod(nBraid,nKeyLen))

    if (nMod==0)
        return(3) // Offset for rightward crossing
    elseif (nMod==1)
        return(-2) // Offset for leftward crossing
    else
        nMod:=Mod(nMod,2)
        if (nMod==0)
            return(-1) // Offset for leftward crossing
        elseif (nMod==1)
            return(2) // Offset for rightward crossing
        endif
    endif

    return(0) // No change

static function GenPwd(nLen as numeric,cKSeed as character)

   local cLet as character
   local cPass as character:=""

   local i as numeric
   local nCnt as numeric:=Len(cKSeed)

   for i:=1 to nLen
      cLet:=SubStr(cKSeed,hb_randomint(nCnt),1)
      cPass+=cLet
   next i

    return(cPass)

// Testing
procedure Main(cEncrypted,cKey)

    local cMessage, cDecrypted as character

    cMessage:="Hello, World!"

    if Empty(cEncrypted) .and. Empty(cKey)
        cEncrypted:=EncryptMessage(cMessage,@cKey)
        ? "Key from Harbour: ", cKey
        ? "Encrypted from Harbour: ", cEncrypted
        cDecrypted:=DecryptMessage(cEncrypted, cKey)
        ? "Decrypted from Harbour: ", cDecrypted+hb_eol()
        cEncrypted:=hb_Base64Encode(cEncrypted)
        cKey:=hb_Base64Encode(cKey)
        ? cEncrypted, cKey
        OutStd(cEncrypted,cKey)
    else
        cEncrypted:=hb_Base64Decode(cEncrypted)
        cKey:=hb_Base64Decode(cKey)
        ? "Encrypted from Parameters: ", cEncrypted
        ? "Key from Parameters: ", cKey
        cDecrypted:=DecryptMessage(cEncrypted, cKey)
        ? "Decrypted from Parameters: ", cDecrypted
    endif

    return
