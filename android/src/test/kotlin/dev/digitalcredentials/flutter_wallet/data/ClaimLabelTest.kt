package dev.digitalcredentials.flutter_wallet.data

import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Claim labels must resolve from either metadata shape.
 *
 * Issuers disagree about where the claim list lives: digital-credentials.dev
 * puts it at the top level of the credential configuration, the EUDI
 * reference issuer nests it under `credential_metadata`. The parser ignores
 * unknown keys, so reading only one shape silently produced raw element ids
 * on three screens at once — the system picker, the issuance sheet and the
 * host's credential list — with nothing logged.
 */
class ClaimLabelTest {

    private val json = Json { ignoreUnknownKeys = true; explicitNulls = false }

    private fun parse(configJson: String) =
        json.decodeFromString<CredentialConfiguration>(configJson)
            as CredentialConfigurationMDoc

    private val nested = """
        {
          "format": "mso_mdoc",
          "doctype": "eu.europa.ec.eudi.employee.1",
          "credential_metadata": {
            "claims": [
              {
                "path": ["eu.europa.ec.eudi.employee.1", "employer_name"],
                "display": [{"locale": "en", "name": "Employer Name"}]
              }
            ]
          }
        }
    """.trimIndent()

    private val topLevel = """
        {
          "format": "mso_mdoc",
          "doctype": "org.iso.18013.5.1.mDL",
          "claims": [
            {
              "path": ["org.iso.18013.5.1", "family_name"],
              "display": [{"locale": "en-US", "name": "Family Name"}]
            }
          ]
        }
    """.trimIndent()

    @Test
    fun `label is read from credential_metadata`() {
        assertEquals(
            "Employer Name",
            parse(nested).displayNameFor("eu.europa.ec.eudi.employee.1", "employer_name"),
        )
    }

    @Test
    fun `label is read from a top-level claims list`() {
        assertEquals(
            "Family Name",
            parse(topLevel).displayNameFor("org.iso.18013.5.1", "family_name"),
        )
    }

    @Test
    fun `an unlabelled element falls back to its identifier`() {
        assertEquals(
            "age_over_21",
            parse(topLevel).displayNameFor("org.iso.18013.5.1", "age_over_21"),
        )
    }

    @Test
    fun `a claim in another namespace does not match`() {
        assertEquals(
            "family_name",
            parse(topLevel).displayNameFor("eu.europa.ec.eudi.employee.1", "family_name"),
        )
    }
}
