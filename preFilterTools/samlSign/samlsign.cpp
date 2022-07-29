/**
 * Licensed to the University Corporation for Advanced Internet
 * Development, Inc. (UCAID) under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for
 * additional information regarding copyright ownership.
 *
 * UCAID licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the
 * License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

/**
 * samlsign.cpp
 *
 * Command-line tool to sign and verify objects.
 */

#if defined (_MSC_VER) || defined(__BORLANDC__)
# include "config_win32.h"
#else
# include "config.h"
#endif

#ifdef WIN32
# define _CRT_NONSTDC_NO_DEPRECATE 1
# define _CRT_SECURE_NO_DEPRECATE 1
#endif

#include <saml/SAMLConfig.h>
#include <saml/saml2/metadata/Metadata.h>
#include <saml/saml2/metadata/MetadataProvider.h>
#include <saml/saml2/metadata/MetadataCredentialCriteria.h>
#include <saml/signature/ContentReference.h>
#include <saml/signature/SignatureProfileValidator.h>
#include <saml/util/SAMLConstants.h>
#include <xmltooling/logging.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/security/Credential.h>
#include <xmltooling/security/SignatureTrustEngine.h>
#include <xmltooling/signature/Signature.h>
#include <xmltooling/signature/SignatureValidator.h>
#include <xmltooling/util/ParserPool.h>
#include <xmltooling/util/XMLHelper.h>

#include <fstream>
#include <xercesc/framework/LocalFileInputSource.hpp>
#include <xercesc/framework/StdInInputSource.hpp>
#include <xercesc/framework/Wrapper4InputSource.hpp>
#include <boost/scoped_ptr.hpp>

using namespace xmlsignature;
using namespace xmlconstants;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace samlconstants;
using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xercesc;
using namespace std;

using boost::scoped_ptr;

template<class T> T* buildPlugin(const char* path, PluginManager<T,string,const DOMElement*>& mgr)
{
    ifstream in(path);
    DOMDocument* doc=XMLToolingConfig::getConfig().getParser().parse(in);
    XercesJanitor<DOMDocument> janitor(doc);

    static const XMLCh _type[] = UNICODE_LITERAL_4(t,y,p,e);
    auto_ptr_char type(doc->getDocumentElement()->getAttributeNS(nullptr,_type));
    if (type.get() && *type.get())
        return mgr.newPlugin(type.get(), doc->getDocumentElement(), false);
    throw XMLToolingException("Missing type in plugin configuration.");
}

CredentialResolver* buildSimpleResolver(const char* key, const char* cert)
{
    static const XMLCh _CredentialResolver[] =  UNICODE_LITERAL_18(C,r,e,d,e,n,t,i,a,l,R,e,s,o,l,v,e,r);
    static const XMLCh _certificate[] =     UNICODE_LITERAL_11(c,e,r,t,i,f,i,c,a,t,e);
    static const XMLCh _key[] =             UNICODE_LITERAL_3(k,e,y);

    DOMDocument* doc = XMLToolingConfig::getConfig().getParser().newDocument();
    XercesJanitor<DOMDocument> janitor(doc);
    DOMElement* root = doc->createElementNS(nullptr, _CredentialResolver);
    if (key) {
        auto_ptr_XMLCh widenit(key);
        root->setAttributeNS(nullptr, _key, widenit.get());
    }
    if (cert) {
        auto_ptr_XMLCh widenit(cert);
        root->setAttributeNS(nullptr, _certificate, widenit.get());
    }

    return XMLToolingConfig::getConfig().CredentialResolverManager.newPlugin(FILESYSTEM_CREDENTIAL_RESOLVER, root, false);
}

class DummyCredentialResolver : public CredentialResolver
{
public:
    DummyCredentialResolver() {}
    ~DummyCredentialResolver() {}

    Lockable* lock() {return this;}
    void unlock() {}

    const Credential* resolve(const CredentialCriteria* criteria=nullptr) const {return nullptr;}
    vector<const Credential*>::size_type resolve(
        vector<const Credential*>& results, const CredentialCriteria* criteria=nullptr
        ) const {return 0;}
};

int main(int argc,char* argv[])
{
    bool verify=true,validate=false;
    char* url_param=nullptr;
    char* path_param=nullptr;
    char* key_param=nullptr;
    char* cert_param=nullptr;
    char* cr_param=nullptr;
    char* t_param=nullptr;
    char* id_param=nullptr;
    char* alg_param=nullptr;
    char* dig_param=nullptr;

    // metadata lookup options
    char* m_param=nullptr;
    char* issuer=nullptr;
    char* prot = nullptr;
    const XMLCh* protocol = nullptr;
    const char* rname = nullptr;
    char* rns = nullptr;

    for (int i=1; i<argc; i++) {
        if (!strcmp(argv[i],"-u") && i+1<argc)
            url_param=argv[++i];
        else if (!strcmp(argv[i],"-f") && i+1<argc)
            path_param=argv[++i];
        else if (!strcmp(argv[i],"-id") && i+1<argc)
            id_param=argv[++i];
        else if (!strcmp(argv[i],"-s"))
            verify=false;
        else if (!strcmp(argv[i],"-k") && i+1<argc)
            key_param=argv[++i];
        else if (!strcmp(argv[i],"-c") && i+1<argc)
            cert_param=argv[++i];
        else if (!strcmp(argv[i],"-R") && i+1<argc)
            cr_param=argv[++i];
        else if (!strcmp(argv[i],"-T") && i+1<argc)
            t_param=argv[++i];
        else if (!strcmp(argv[i],"-M") && i+1<argc)
            m_param=argv[++i];
        else if (!strcmp(argv[i],"-i") && i+1<argc)
            issuer=argv[++i];
        else if (!strcmp(argv[i],"-p") && i+1<argc)
            prot=argv[++i];
        else if (!strcmp(argv[i],"-r") && i+1<argc)
            rname=argv[++i];
        else if (!strcmp(argv[i],"-V"))
            validate = true;
        else if (!strcmp(argv[i],"-ns") && i+1<argc)
            rns=argv[++i];
        else if (!strcmp(argv[i],"-alg") && i+1<argc)
            alg_param=argv[++i];
        else if (!strcmp(argv[i],"-dig") && i+1<argc)
            dig_param=argv[++i];
        else if (!strcmp(argv[i],"-saml10"))
            protocol=samlconstants::SAML10_PROTOCOL_ENUM;
        else if (!strcmp(argv[i],"-saml11"))
            protocol=samlconstants::SAML11_PROTOCOL_ENUM;
        else if (!strcmp(argv[i],"-saml2"))
            protocol=samlconstants::SAML20P_NS;
        else if (!strcmp(argv[i],"-idp"))
            rname="IDPSSODescriptor";
        else if (!strcmp(argv[i],"-aa"))
            rname="AttributeAuthorityDescriptor";
        else if (!strcmp(argv[i],"-pdp"))
            rname="PDPDescriptor";
        else if (!strcmp(argv[i],"-sp"))
            rname="SPSSODescriptor";
    }

    if (verify && !cert_param && !cr_param && !t_param) {
        cerr << "either -c or -R or -T option required when verifiying, see documentation for usage" << endl;
        return -1;
    }
    else if (!verify && !key_param && !cr_param) {
        cerr << "either -k or -R option required when signing, see documentation for usage" << endl;
        return -1;
    }

    XMLToolingConfig& xmlconf = XMLToolingConfig::getConfig();
    xmlconf.log_config(getenv("OPENSAML_LOG_CONFIG"));
    SAMLConfig& conf=SAMLConfig::getConfig();
    if (!conf.init())
        return -2;

    if (getenv("OPENSAML_SCHEMAS"))
        xmlconf.getValidatingParser().loadCatalogs(getenv("OPENSAML_SCHEMAS"));

    Category& log = Category::getInstance("OpenSAML.Utility.SAMLSign");

    int ret = 0;

    try {
        // Parse the specified document.
        DOMDocument* doc=nullptr;
        if (url_param) {
            auto_ptr_XMLCh wideurl(url_param);
            URLInputSource src(wideurl.get());
            Wrapper4InputSource dsrc(&src,false);
            if (validate)
                doc = xmlconf.getValidatingParser().parse(dsrc);
            else
                doc = xmlconf.getParser().parse(dsrc);
        }
        else if (path_param) {
            auto_ptr_XMLCh widenit(path_param);
            LocalFileInputSource src(widenit.get());
            Wrapper4InputSource dsrc(&src,false);
            if (validate)
                doc = xmlconf.getValidatingParser().parse(dsrc);
            else
                doc = xmlconf.getParser().parse(dsrc);
        }
        else {
            StdInInputSource src;
            Wrapper4InputSource dsrc(&src,false);
            if (validate)
                doc = xmlconf.getValidatingParser().parse(dsrc);
            else
                doc = xmlconf.getParser().parse(dsrc);
        }

        // Unmarshall it.
        XercesJanitor<DOMDocument> jan(doc);
        scoped_ptr<XMLObject> sourcewrapper(XMLObjectBuilder::buildOneFromElement(doc->getDocumentElement(), true));
        jan.release();

        // Navigate to the selected node, or use the root if no ID specified.
        // Then make sure it's a SignableSAMLObject.
        XMLObject* source = sourcewrapper.get();
        if (id_param) {
            auto_ptr_XMLCh widenit(id_param);
            source = XMLHelper::getXMLObjectById(*source, widenit.get());
            if (!source)
                throw XMLToolingException("Element with ID ($1) not found.", params(1,id_param));
        }
        SignableObject* signable = dynamic_cast<SignableObject*>(source);
        if (!signable)
            throw XMLToolingException("Input is not a signable SAML object.");

        if (verify) {
            if (!signable->getSignature())
                throw SignatureException("Cannot verify unsigned object.");

            // Check the profile.
            SignatureProfileValidator sigval;
            sigval.validate(signable->getSignature());

            if (cert_param || cr_param) {
                // Build a resolver to supply trusted credentials.
                auto_ptr<CredentialResolver> cr(
                    cr_param ? buildPlugin(cr_param, xmlconf.CredentialResolverManager) : buildSimpleResolver(nullptr, cert_param)
                    );
                Locker locker(cr.get());

                // Set up criteria.
                CredentialCriteria cc;
                cc.setUsage(Credential::SIGNING_CREDENTIAL);
                cc.setSignature(*(signable->getSignature()), CredentialCriteria::KEYINFO_EXTRACTION_KEY);
                if (issuer)
                    cc.setPeerName(issuer);

                // Try every credential we can find.
                vector<const Credential*> creds;
                if (cr->resolve(creds, &cc)) {
                    bool good=false;
                    SignatureValidator sigValidator;
                    for (vector<const Credential*>::const_iterator i = creds.begin(); i != creds.end(); ++i) {
                        try {
                            sigValidator.setCredential(*i);
                            sigValidator.validate(signable->getSignature());
                            log.info("successful signature verification");
                            good = true;
                            break;
                        }
                        catch (exception& e) {
                            log.info("error trying verification key: %s", e.what());
                        }
                    }
                    if (!good)
                        throw SignatureException("CredentialResolver did not supply a successful verification key.");
                }
                else {
                    throw SignatureException("CredentialResolver did not supply any verification keys.");
                }
            }
            else {
                // TrustEngine-based verification, so try and build the plugins.
                auto_ptr<TrustEngine> trust(buildPlugin(t_param, xmlconf.TrustEngineManager));
                SignatureTrustEngine* sigtrust = dynamic_cast<SignatureTrustEngine*>(trust.get());
                if (m_param && rname && issuer) {
                    if (!protocol) {
                        if (prot)
                            protocol = XMLString::transcode(prot);
                    }
                    if (!protocol) {
                        conf.term();
                        cerr << "use of metadata option requires a protocol option" << endl;
                        return -1;
                    }
                    scoped_ptr<MetadataProvider> metadata(buildPlugin(m_param, conf.MetadataProviderManager));
                    metadata->init();

                    const XMLCh* ns = rns ? XMLString::transcode(rns) : samlconstants::SAML20MD_NS;
                    auto_ptr_XMLCh n(rname);
                    xmltooling::QName q(ns, n.get());

                    Locker locker(metadata.get());
                    MetadataProvider::Criteria mc(issuer, &q, protocol);
                    pair<const EntityDescriptor*,const RoleDescriptor*> entity = metadata->getEntityDescriptor(mc);
                    if (!entity.first)
                        throw MetadataException("no metadata found for ($1)", params(1, issuer));
                    else if (!entity.second)
                        throw MetadataException("compatible role $1 not found for ($2)", params(2, q.toString().c_str(), issuer));

                    MetadataCredentialCriteria mcc(*entity.second);
                    if (sigtrust->validate(*signable->getSignature(), *metadata.get(), &mcc))
                        log.info("successful signature verification");
                    else
                        throw SignatureException("Unable to verify signature with TrustEngine and supplied metadata.");
                }
                else {
                    // Set up criteria.
                    CredentialCriteria cc;
                    cc.setUsage(Credential::SIGNING_CREDENTIAL);
                    cc.setSignature(*(signable->getSignature()), CredentialCriteria::KEYINFO_EXTRACTION_KEY);
                    if (issuer)
                        cc.setPeerName(issuer);
                    DummyCredentialResolver dummy;
                    if (sigtrust->validate(*signable->getSignature(), dummy, &cc))
                        log.info("successful signature verification");
                    else
                        throw SignatureException("Unable to verify signature with TrustEngine (no metadata supplied).");
                }
            }
        }
        else {
            // Build a resolver to supply a credential.
            scoped_ptr<CredentialResolver> cr(
                cr_param ? buildPlugin(cr_param, xmlconf.CredentialResolverManager) : buildSimpleResolver(key_param, cert_param)
                );
            Locker locker(cr.get());
            CredentialCriteria cc;
            cc.setUsage(Credential::SIGNING_CREDENTIAL);
            const Credential* cred = cr->resolve(&cc);
            if (!cred)
                throw XMLSecurityException("Unable to resolve a signing credential.");

            // Attach new signature.
            Signature* sig = SignatureBuilder::buildSignature();
            signable->setSignature(sig);
            auto_ptr_XMLCh alg(alg_param);
            if (alg.get()) {
                sig->setSignatureAlgorithm(alg.get());
            }
            auto_ptr_XMLCh dig(dig_param);
            if (dig.get()) {
            	dynamic_cast<opensaml::ContentReference*>(sig->getContentReference())->setDigestAlgorithm(dig.get());
            }

            // Sign response while re-marshalling.
            vector<Signature*> sigs(1,sig);
            XMLHelper::serialize(signable->marshall((DOMDocument*)nullptr,&sigs,cred), cout);
        }
    }
    catch(exception& e) {
        log.errorStream() << "caught an exception: " << e.what() << logging::eol;
        ret=-10;
    }

    conf.term();
    return ret;
}
