package dev.digitalcredentials.flutter_wallet.openid4vp

import android.util.Log
import dev.digitalcredentials.flutter_wallet.data.CredentialItem
import dev.digitalcredentials.flutter_wallet.decodeBase64UrlNoPadding
import dev.digitalcredentials.flutter_wallet.mdoc.MDoc
import dev.digitalcredentials.flutter_wallet.data.CredentialConfigurationMDoc
import dev.digitalcredentials.flutter_wallet.data.CredentialConfigurationUnknownFormat
import org.json.JSONArray
import org.json.JSONObject

abstract class MatchedClaim

class MatchedMDocClaim(val namespace: String, val claimName: String) : MatchedClaim()

data class MatchedCredential(
    val id: String,
    val matchedClaims: MutableList<MatchedClaim> = mutableListOf()
)

fun getDqclCredentialById(query: JSONObject, id: String): JSONObject? {
    require(query.has("credentials")) { "dcql_query must contain a credentials" }
    val credentials = query.getJSONArray("credentials")
    for (i in 0..<credentials.length()) {
        val dcqlCred = credentials.getJSONObject(i)
        if (dcqlCred.optString("id") == id) {
            return dcqlCred
        }
    }
    return null
}

fun performQueryOnCredential(
    query: JSONObject,
    selectedCredential: CredentialItem,
    dcqlCredId: String? // Only support a single document
): OpenId4VPMatchedCredential {
    require(query.has("credentials")) { "dcql_query must contain a credentials" }
    val credentials = query.getJSONArray("credentials")
    val credential = if (dcqlCredId == null) {
        require(credentials.length() == 1) { "Only support a single document" }
        credentials.getJSONObject(0)!!
    } else {
        credentials.let {
            for (i in 0..<it.length()) {
                val dcqlCred = it.getJSONObject(i)
                if (dcqlCred.optString("id") == dcqlCredId) {
                    return@let dcqlCred
                }
            }
            throw IllegalStateException("Could not find a matching dcql credential query")
        }
    }

    require(credential.has("id")) { "dcql_query credential must contain an id" }
    val dcqlId = credential.getString(("id"))


    // Run the query on the selected credential
    val format = credential.getString(("format"))
    val meta = credential.opt("meta") as JSONObject?
    val claims = credential.opt("claims") as JSONArray?
    val claimSets = credential.opt("claim_sets") as JSONArray?

    require(!(claims == null && claimSets != null)) { "dcql_query credential must contains claim_sets without claims" }

    // Check format
    require(selectedCredential.config.format == format) { "selected credentials format does not match" }

    // TODO: Check doctype
    if (claims == null) {
        Log.i("DCQL", "Matching without claims")
        when (selectedCredential.config) {
            is CredentialConfigurationMDoc -> {
                val mdoc =
                    MDoc(selectedCredential.credentials.first().credential.decodeBase64UrlNoPadding())
                val ret = mutableMapOf<String, List<String>>()
                mdoc.issuerSignedNamespaces.forEach { (namespace, elements) ->
                    ret[namespace] = elements.keys.toList()
                }
                return OpenId4VPMatchedCredential(
                    dcqlId = dcqlId,
                    matchedClaims = OpenId4VPMatchedMDocClaims(listOf(ret))
                )
            }

            is CredentialConfigurationUnknownFormat ->
                throw UnsupportedOperationException(
                    "unsupported credential format: ${selectedCredential.config.format}")
        }
    } else {
        Log.i("DCQL", "Matching with claims")
        if (claimSets == null) {
            Log.i("DCQL", "Matching without claim_sets")
            when (selectedCredential.config) {
                is CredentialConfigurationMDoc -> {
                    val mdoc =
                        MDoc(selectedCredential.credentials.first().credential.decodeBase64UrlNoPadding())
                    val ret = mutableMapOf<String, MutableList<String>>()
                    for (claimIdx in 0 until claims.length()) {
                        val claim = claims.getJSONObject(claimIdx)!!
                        val path = claim.getJSONArray("path")
                        val claimNamespace = path.get(0)
                        val claimName = path.getString(1)

                        mdoc.issuerSignedNamespaces.forEach { (namespace, elements) ->
                            if (namespace == claimNamespace) {
                                elements.forEach { (element, value) ->
                                    if (claimName == element) {
                                        if (ret.containsKey(namespace)) {
                                            ret[namespace]?.add(claimName)
                                        } else {
                                            ret[namespace] = mutableListOf(claimName)
                                        }
                                    }
                                }
                            }
                        }
                    }
                    return OpenId4VPMatchedCredential(
                        dcqlId = dcqlId,
                        matchedClaims = OpenId4VPMatchedMDocClaims(listOf(ret))
                    )
                }

                is CredentialConfigurationUnknownFormat ->
                throw UnsupportedOperationException(
                    "unsupported credential format: ${selectedCredential.config.format}")
            }
        } else {
            Log.i("DCQL", "Matching with claim_sets")
            when (selectedCredential.config) {
                is CredentialConfigurationMDoc -> {
                    val mdoc =
                        MDoc(selectedCredential.credentials.first().credential.decodeBase64UrlNoPadding())
                    val claimSetsRet: MutableList<Map<String, List<String>>> = mutableListOf()
                    for (i in 0..<claimSets.length()) {
                        val claimSet = claimSets.getJSONArray(i)
                        val ret = mutableMapOf<String, MutableList<String>>()
                        for (j in 0 until claimSet.length()) {
                            val claimId = claimSet.getString(j)
                            val claim = findClaim(claims, claimId)!!
                            val path = claim.getJSONArray("path")
                            val claimNamespace = path.get(0)
                            val claimName = path.getString(1)

                            mdoc.issuerSignedNamespaces.forEach { (namespace, elements) ->
                                if (namespace == claimNamespace) {
                                    elements.forEach { (element, value) ->
                                        if (claimName == element) {
                                            if (ret.containsKey(namespace)) {
                                                ret[namespace]?.add(claimName)
                                            } else {
                                                ret[namespace] = mutableListOf(claimName)
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        claimSetsRet.add(ret)
                    }
                    return OpenId4VPMatchedCredential(
                        dcqlId = dcqlId,
                        matchedClaims = OpenId4VPMatchedMDocClaims(claimSetsRet)
                    )
                }
                is CredentialConfigurationUnknownFormat ->
                throw UnsupportedOperationException(
                    "unsupported credential format: ${selectedCredential.config.format}")
            }
        }
    }
}

private fun findClaim(claims: JSONArray, claimId: String): JSONObject? {
    for (i in 0..< claims.length()) {
        val claim = claims.getJSONObject(i)
        if (claim.has("id") && claim.getString("id") == claimId) {
            return claim
        }
    }
    return null
}


fun DCQLQuery(
    query: JSONObject,
    credentialStore: JSONObject
): Map<String, List<MatchedCredential>> {
    require(query.has("credentials")) { "dcql_query must contain a credentials" }
    val credentials = query.getJSONArray("credentials")
    require(credentials.length() == 1) { "Only support returning a single document" }
    val credential = credentials.getJSONObject(0)!!

    require(credential.has("id")) { "dcql_query credential must contain an id" }
    val id = credential.getString(("id"))
    val matchedCredentials =
        matchCredential(credential, credentialStore.getJSONObject("credentials"))
    Log.i("DCQL", "matchedCredentials $matchedCredentials")
    return mapOf(Pair(id, matchedCredentials))
}

fun matchCredential(credential: JSONObject, credentialStore: JSONObject): List<MatchedCredential> {
    require(credential.has("format")) { "dcql_query credential must contain a format" }

    val matchedCredentials = mutableListOf<MatchedCredential>()


    val format = credential.getString(("format"))

    val meta = credential.opt("meta") as JSONObject?
    val claims = credential.opt("claims") as JSONArray?
    val claimSets = credential.opt("claim_sets") as JSONArray?

    require(!(claims == null && claimSets != null)) { "dcql_query credential must contains claim_sets without claims" }

    // Filter by format
    val candidatesByFormat = credentialStore.opt(format) as JSONObject? ?: return matchedCredentials

    Log.i("DCQL", "candidatesByFormat $candidatesByFormat")

    val candidatesByMeta: JSONArray
    // Filter on the meta
    if (meta != null) {
        when (format) {
            "mso_mdoc" -> {
                val docType = meta.opt("doctype_value") as String? ?: return matchedCredentials
                Log.i("DCQL", "doctype $docType")
                if (candidatesByFormat.has(docType)) {
                    candidatesByMeta = candidatesByFormat.getJSONArray(docType)
                } else {
                    return matchedCredentials
                }

            }

            else -> return matchedCredentials
        }
    } else {
        // TODO: fix the fact that doctype is required at the moment.
        return matchedCredentials
    }

    Log.i("DCQL", "candidatesByMeta $candidatesByMeta")

    if (claims == null) {
        Log.i("DCQL", "Matching without claims")
    } else {
        Log.i("DCQL", "Matching with claims")
        if (claimSets == null) {
            Log.i("DCQL", "Matching without claim_sets")
            for (candidateIdx in 0 until candidatesByMeta.length()) {
                val candidate = candidatesByMeta.getJSONObject(candidateIdx)!!
                val matchedCredential = MatchedCredential(candidate.getString("id"))

                for (claimIdx in 0 until claims.length()) {
                    val claim = claims.getJSONObject(claimIdx)!!
                    val claimValues = claim.opt("values") as JSONArray?
                    when (format) {
                        "mso_mdoc" -> {
                            require(claim.has("namespace")) { "mdoc claim credential must contain namespace" }
                            require(claim.has("claim_name")) { "mdoc claim credential must contain claim_name" }
                            val namespace = claim.getString("namespace")
                            val claimName = claim.getString("claim_name")
                            if (candidate.getJSONObject("namespaces").has(namespace)) {
                                if (candidate.getJSONObject("namespaces").getJSONObject(namespace)
                                        .has(claimName)
                                ) {
                                    matchedCredential.matchedClaims.add(
                                        MatchedMDocClaim(
                                            namespace,
                                            claimName
                                        )
                                    )
                                }
                            }
                        }
                    }
                }
                if (claims.length() == matchedCredential.matchedClaims.size) {
                    matchedCredentials.add(matchedCredential)
                }
            }
        }
    }
    return matchedCredentials
}