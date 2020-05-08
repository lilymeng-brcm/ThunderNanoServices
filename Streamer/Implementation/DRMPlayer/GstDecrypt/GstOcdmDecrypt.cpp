/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2020 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "GstOcdmDecrypt.h"
#include "open_cdm_adapter.h"
#include <array>
#include <core/Queue.h>
#include <gst/base/gstbasetransform.h>
#include <gst/gst.h>
#include <gst/gstprotection.h>
#include <map>
#include <vector>

GST_DEBUG_CATEGORY_STATIC(gst_ocdmdecrypt_debug_category);
#define GST_CAT_DEFAULT gst_ocdmdecrypt_debug_category

G_DEFINE_TYPE_WITH_CODE(GstOcdmdecrypt, gst_ocdmdecrypt, GST_TYPE_BASE_TRANSFORM,
    GST_DEBUG_CATEGORY_INIT(gst_ocdmdecrypt_debug_category, "ocdmdecrypt", 0,
        "debug category for ocdmdecrypt element"));
constexpr static auto clearContentTypes = { "video/mp4", "audio/mp4", "audio/mpeg", "video/x-h264" };

// TODO: This information should be returned from OpenCDM.
static std::map<string, string> keySystems{ { "edef8ba9-79d6-4ace-a3c8-27dcd51d21ed", "com.widevine.alpha" },
    { "9a04f079-9840-4286-ab92-e65be0885f95", "com.microsoft.playready" } };
constexpr static auto cencPrefix = "application/x-cenc";

struct _GstOcdmdecryptImpl {
    OpenCDMSystem* _ocdmSystem;
    OpenCDMSession* _ocdmSession;
    WPEFramework::Challenger _challenger;
};

// Overwritten GstBaseTransform callbacks:
static GstCaps* TransformCaps(GstBaseTransform* trans, GstPadDirection direction,
    GstCaps* caps, GstCaps* filter);
static gboolean HandleProtectionEvent(GstOcdmdecrypt* ocdmdecrypt, const char* systemId,
    GstBuffer* data);
static gboolean SinkEvent(GstBaseTransform* trans, GstEvent* event);
static GstFlowReturn TransformIp(GstBaseTransform* trans, GstBuffer* buffer);
static void Finalize(GObject* object);

static void AddCapsForKeysystem(GstCaps*& caps, const string& keysystem)
{
    for (auto& type : clearContentTypes) {
        gst_caps_append_structure(caps,
            gst_structure_new(cencPrefix,
                "original-media-type", G_TYPE_STRING, type,
                "protection-system", G_TYPE_STRING, keysystem.c_str(), NULL));
    }
}
static GstCaps* SinkCaps()
{
    GstCaps* cencCaps = gst_caps_new_empty();
    for (auto& system : keySystems) {
        if (opencdm_is_type_supported(system.second.c_str(), "") == OpenCDMError::ERROR_NONE) {
            AddCapsForKeysystem(cencCaps, system.first);
        } else {
            GST_WARNING("Keysystem <%s> is not supported by ocdm.", system.second.c_str());
        }
    }
    return cencCaps;
}

static GstCaps* SrcCaps()
{
    GstCaps* caps = gst_caps_new_empty();
    for (auto& type : clearContentTypes)
        gst_caps_append_structure(caps, gst_structure_new_from_string(type));
    return caps;
}

static void
gst_ocdmdecrypt_class_init(GstOcdmdecryptClass* klass)
{
    GstBaseTransformClass* base_transform_class = GST_BASE_TRANSFORM_CLASS(klass);

    gst_element_class_add_pad_template(GST_ELEMENT_CLASS(klass),
        gst_pad_template_new("src", GST_PAD_SRC, GST_PAD_ALWAYS, SrcCaps()));

    gst_element_class_add_pad_template(GST_ELEMENT_CLASS(klass),
        gst_pad_template_new("sink", GST_PAD_SINK, GST_PAD_ALWAYS, SinkCaps()));

    gst_element_class_set_static_metadata(GST_ELEMENT_CLASS(klass),
        "FIXME Long name", GST_ELEMENT_FACTORY_KLASS_DECRYPTOR, "FIXME Description",
        "FIXME <fixme@example.com>");

    G_OBJECT_CLASS(klass)->finalize = Finalize;
    base_transform_class->transform_ip_on_passthrough = TRUE;

    base_transform_class->transform_caps = GST_DEBUG_FUNCPTR(TransformCaps);

    // TODO:
    base_transform_class->accept_caps = [](GstBaseTransform* trans, GstPadDirection direction,
                                            GstCaps* caps) -> gboolean {
        GST_FIXME_OBJECT(GST_OCDMDECRYPT(trans), "Element accepts all caps");
        return TRUE;
    };

    base_transform_class->transform_ip = GST_DEBUG_FUNCPTR(TransformIp);
    base_transform_class->sink_event = GST_DEBUG_FUNCPTR(SinkEvent);
}

static void gst_ocdmdecrypt_init(GstOcdmdecrypt* ocdmdecrypt)
{
    GstBaseTransform* base = GST_BASE_TRANSFORM(ocdmdecrypt);
    gst_base_transform_set_in_place(base, TRUE);
    gst_base_transform_set_passthrough(base, FALSE);
    gst_base_transform_set_gap_aware(base, FALSE);

    ocdmdecrypt->impl = std::move(std::unique_ptr<GstOcdmDecryptImpl>(new GstOcdmDecryptImpl()));
    ocdmdecrypt->impl->_ocdmSession = nullptr;
    ocdmdecrypt->impl->_ocdmSystem = nullptr;

    GST_FIXME_OBJECT(ocdmdecrypt, "Pretty bad leaks");
    GST_FIXME_OBJECT(ocdmdecrypt, "Decryption doesn't wait for the key status");
    GST_FIXME_OBJECT(ocdmdecrypt, "Flushing the pipeline doesn't free ocdm system/session");
    GST_FIXME_OBJECT(ocdmdecrypt, "Element is accepting all caps");
    GST_FIXME_OBJECT(ocdmdecrypt, "Upstream caps transformation not implemented");
    GST_FIXME_OBJECT(ocdmdecrypt, "Caps are constructed based on hard coded keysystem values");
    GST_FIXME_OBJECT(ocdmdecrypt, "Element doesn't handle dash manifests - mpd");
}

static void clearCencStruct(GstStructure*& structure)
{
    gst_structure_set_name(structure, gst_structure_get_string(structure, "original-media-type"));
    gst_structure_remove_field(structure, "protection-system");
    gst_structure_remove_field(structure, "original-media-type");
}

static GstCaps* TransformCaps(GstBaseTransform* trans, GstPadDirection direction,
    GstCaps* caps, GstCaps* filter)
{
    GstOcdmdecrypt* ocdmdecrypt = GST_OCDMDECRYPT(trans);
    GstCaps* othercaps;

    GST_DEBUG_OBJECT(ocdmdecrypt, "transform_caps");
    GST_FIXME_OBJECT(ocdmdecrypt, "Upstream caps transformation not implemented");

    if (direction == GST_PAD_SRC) {
        // TODO:
        // Fired on reconfigure events.
        othercaps = gst_caps_copy(caps);
    } else {
        GST_INFO("Transforming caps going downstream");
        othercaps = gst_caps_new_empty();
        size_t size = gst_caps_get_size(caps);
        for (size_t index = 0; index < size; ++index) {
            GstStructure* upstreamStruct = gst_caps_get_structure(caps, index);
            GstStructure* copyUpstream = gst_structure_copy(upstreamStruct);

            // Removes all fields related to encryption, so the downstream caps intersection succeeds.
            clearCencStruct(copyUpstream);
            // "othercaps" become the owner of the "copyUpstream" structure, so no need to free.
            gst_caps_append_structure(othercaps, copyUpstream);
        }
    }

    if (filter) {
        GstCaps* intersect;
        othercaps = gst_caps_copy(caps);
        intersect = gst_caps_intersect(othercaps, filter);
        gst_caps_unref(othercaps);
        othercaps = intersect;
    }
    return othercaps;
}

static gboolean HandleProtectionEvent(GstOcdmdecrypt* ocdmdecrypt, const char* systemId, GstBuffer* data)
{
    if (ocdmdecrypt->impl->_ocdmSystem == nullptr) {
        string keysystem = keySystems[systemId];

        if (keysystem.empty()) {
            TRACE_L1("Cannot initialize ocdm for keysystem: %s", systemId);
            return FALSE;
        }

        ocdmdecrypt->impl->_ocdmSystem = opencdm_create_system(keysystem.c_str());

        if (ocdmdecrypt->impl->_ocdmSession == nullptr) {
            GstMapInfo dataView;
            gst_buffer_map(data, &dataView, GST_MAP_READ);
            opencdm_construct_session(ocdmdecrypt->impl->_ocdmSystem,
                LicenseType::Temporary,
                "cenc",
                dataView.data,
                static_cast<uint16_t>(dataView.size),
                nullptr,
                0,
                &ocdmdecrypt->impl->_challenger.OcdmCallbacks(),
                &ocdmdecrypt->impl->_challenger,
                &ocdmdecrypt->impl->_ocdmSession);

            string response;
            ocdmdecrypt->impl->_challenger.KeyResponse(response);
            const uint8_t* keyResponse = reinterpret_cast<const uint8_t*>(response.c_str());

            OpenCDMError err = opencdm_session_update(ocdmdecrypt->impl->_ocdmSession, keyResponse, response.length());

            gst_buffer_unmap(data, &dataView);

            ASSERT(err == OpenCDMError::ERROR_NONE);
            ASSERT(ocdmdecrypt->impl->_ocdmSession != nullptr);
        }
    }
    return TRUE;
}

static gboolean SinkEvent(GstBaseTransform* trans, GstEvent* event)
{
    GstOcdmdecrypt* ocdmdecrypt = GST_OCDMDECRYPT(trans);
    GST_DEBUG_OBJECT(ocdmdecrypt, "sink_event");

    switch (GST_EVENT_TYPE(event)) {
    case GST_EVENT_PROTECTION: {
        const char* systemId = nullptr;
        GstBuffer* data = nullptr;

        gst_event_parse_protection(event, &systemId, &data, NULL);

        GST_FIXME_OBJECT(ocdmdecrypt, "HandleProtectionEvent function most likely leaks some buffers");

        HandleProtectionEvent(ocdmdecrypt, systemId, data);

        gst_buffer_unref(data);
        gst_event_unref(event);

        return GST_BASE_TRANSFORM_CLASS(gst_ocdmdecrypt_parent_class)->sink_event(trans, event);
    }
    default: {
        return GST_BASE_TRANSFORM_CLASS(gst_ocdmdecrypt_parent_class)->sink_event(trans, event);
    }
    }
}

static GstFlowReturn TransformIp(GstBaseTransform* trans, GstBuffer* buffer)
{
    GstOcdmdecrypt* ocdmdecrypt = GST_OCDMDECRYPT(trans);

    GST_DEBUG_OBJECT(ocdmdecrypt, "transform_ip");

    GstProtectionMeta* protectionMeta = reinterpret_cast<GstProtectionMeta*>(gst_buffer_get_protection_meta(buffer));
    if (!protectionMeta) {
        return GST_FLOW_OK;
    } else {

        // const GValue* streamEncryptionEventsList = gst_structure_get_value(protectionMeta->info, "stream-encryption-events");
        gst_structure_remove_field(protectionMeta->info, "stream-encryption-events");

        const GValue* value;
        value = gst_structure_get_value(protectionMeta->info, "kid");

        GstBuffer* keyIDBuffer = nullptr;
        keyIDBuffer = gst_value_get_buffer(value);
        GstMapInfo mappedKeyId;
        gst_buffer_map(keyIDBuffer, &mappedKeyId, GST_MAP_READ);
        opencdm_session_status(ocdmdecrypt->impl->_ocdmSession, mappedKeyId.data, mappedKeyId.size);

        unsigned ivSize;
        gst_structure_get_uint(protectionMeta->info, "iv_size", &ivSize);

        gboolean encrypted;
        gst_structure_get_boolean(protectionMeta->info, "encrypted", &encrypted);

        if (!ivSize || !encrypted) {
            gst_buffer_remove_meta(buffer, reinterpret_cast<GstMeta*>(protectionMeta));
            return GST_FLOW_OK;
        }

        unsigned subSampleCount;
        gst_structure_get_uint(protectionMeta->info, "subsample_count", &subSampleCount);

        const GValue* value2;
        GstBuffer* subSamplesBuffer = nullptr;
        if (subSampleCount) {
            value2 = gst_structure_get_value(protectionMeta->info, "subsamples");
            subSamplesBuffer = gst_value_get_buffer(value2);
        }

        const GValue* value3;
        value3 = gst_structure_get_value(protectionMeta->info, "iv");
        GstBuffer* ivBuffer = gst_value_get_buffer(value3);

        if (subSamplesBuffer != nullptr && ivBuffer != nullptr && keyIDBuffer != nullptr) {
            opencdm_gstreamer_session_decrypt(ocdmdecrypt->impl->_ocdmSession, buffer, subSamplesBuffer, subSampleCount, ivBuffer, keyIDBuffer, 0);
            gst_buffer_remove_meta(buffer, reinterpret_cast<GstMeta*>(protectionMeta));
            return GST_FLOW_OK;
        } else {
            gst_buffer_remove_meta(buffer, reinterpret_cast<GstMeta*>(protectionMeta));
            GST_ERROR_OBJECT(ocdmdecrypt, "Missing decryption data");
            return GST_FLOW_NOT_SUPPORTED;
        }
    }
}

void Finalize(GObject* object)
{
    GstOcdmdecrypt* ocdmdecrypt = GST_OCDMDECRYPT(object);
    GST_DEBUG_OBJECT(ocdmdecrypt, "finalize");
    G_OBJECT_CLASS(gst_ocdmdecrypt_parent_class)->finalize(object);
}
