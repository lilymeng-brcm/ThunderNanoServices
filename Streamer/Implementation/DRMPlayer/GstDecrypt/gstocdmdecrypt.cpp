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

#include "gstocdmdecrypt.h"
#include <gst/base/gstbasetransform.h>
#include <gst/gst.h>
#include <gst/gstprotection.h>

#include "Challenger.h"

GST_DEBUG_CATEGORY_STATIC(gst_ocdmdecrypt_debug_category);
#define GST_CAT_DEFAULT gst_ocdmdecrypt_debug_category

static void gst_ocdmdecrypt_finalize(GObject* object);

static GstCaps* gst_ocdmdecrypt_transform_caps(GstBaseTransform* trans,
    GstPadDirection direction, GstCaps* caps, GstCaps* filter);
static gboolean gst_ocdmdecrypt_accept_caps(GstBaseTransform* trans,
    GstPadDirection direction, GstCaps* caps);
static gboolean gst_ocdmdecrypt_sink_event(GstBaseTransform* trans,
    GstEvent* event);
static GstFlowReturn gst_ocdmdecrypt_transform_ip(GstBaseTransform* trans,
    GstBuffer* buf);

static GstStaticPadTemplate gst_ocdmdecrypt_src_template = GST_STATIC_PAD_TEMPLATE("src",
    GST_PAD_SRC,
    GST_PAD_ALWAYS,
    GST_STATIC_CAPS(
        "video/mp4; "
        "audio/mp4; "
        "audio/mpeg; "
        "video/x-h264; "));

// TODO: Ask ocdm for the available keysystems
// --------------------------------------------

static GstStaticPadTemplate gst_ocdmdecrypt_sink_template = GST_STATIC_PAD_TEMPLATE("sink",
    GST_PAD_SINK,
    GST_PAD_ALWAYS,
    GST_STATIC_CAPS(
        "application/x-cenc, original-media-type=video/x-h264,  protection-system=edef8ba9-79d6-4ace-a3c8-27dcd51d21ed; " // Widevine
        "application/x-cenc, original-media-type=video/mp4,     protection-system=edef8ba9-79d6-4ace-a3c8-27dcd51d21ed; "
        "application/x-cenc, original-media-type=audio/mp4,     protection-system=edef8ba9-79d6-4ace-a3c8-27dcd51d21ed; "
        "application/x-cenc, original-media-type=audio/mepeg,   protection-system=edef8ba9-79d6-4ace-a3c8-27dcd51d21ed; "
        "application/x-cenc, original-media-type=video/x-h264,  protection-system=9a04f079-9840-4286-ab92-e65be0885f95; " // Playready
        "application/x-cenc, original-media-type=video/mp4,     protection-system=9a04f079-9840-4286-ab92-e65be0885f95; "
        "application/x-cenc, original-media-type=audio/mp4,     protection-system=9a04f079-9840-4286-ab92-e65be0885f95; "
        "application/x-cenc, original-media-type=audio/mepeg,   protection-system=9a04f079-9840-4286-ab92-e65be0885f95; "));

G_DEFINE_TYPE_WITH_CODE(GstOcdmdecrypt, gst_ocdmdecrypt, GST_TYPE_BASE_TRANSFORM,
    GST_DEBUG_CATEGORY_INIT(gst_ocdmdecrypt_debug_category, "ocdmdecrypt", 0,
        "debug category for ocdmdecrypt element"));

static void
gst_ocdmdecrypt_class_init(GstOcdmdecryptClass* klass)
{
    GObjectClass* gobject_class = G_OBJECT_CLASS(klass);
    GstBaseTransformClass* base_transform_class = GST_BASE_TRANSFORM_CLASS(klass);

    // opencdm_create_system

    gst_element_class_add_pad_template(GST_ELEMENT_CLASS(klass), gst_static_pad_template_get(&gst_ocdmdecrypt_sink_template));

    gst_element_class_add_pad_template(GST_ELEMENT_CLASS(klass), gst_static_pad_template_get(&gst_ocdmdecrypt_src_template));

    gst_element_class_set_static_metadata(GST_ELEMENT_CLASS(klass),
        "FIXME Long name", GST_ELEMENT_FACTORY_KLASS_DECRYPTOR, "FIXME Description",
        "FIXME <fixme@example.com>");

    gobject_class->finalize = gst_ocdmdecrypt_finalize;
    base_transform_class->transform_ip_on_passthrough = FALSE;

    base_transform_class->transform_caps = GST_DEBUG_FUNCPTR(gst_ocdmdecrypt_transform_caps);
    base_transform_class->accept_caps = GST_DEBUG_FUNCPTR(gst_ocdmdecrypt_accept_caps);
    base_transform_class->transform_ip = GST_DEBUG_FUNCPTR(gst_ocdmdecrypt_transform_ip);
    base_transform_class->sink_event = GST_DEBUG_FUNCPTR(gst_ocdmdecrypt_sink_event);
}

static void gst_ocdmdecrypt_init(GstOcdmdecrypt* ocdmdecrypt)
{
    GstBaseTransform* base = GST_BASE_TRANSFORM(ocdmdecrypt);
    gst_base_transform_set_in_place(base, TRUE);
    gst_base_transform_set_passthrough(base, FALSE);
    gst_base_transform_set_gap_aware(base, FALSE);
}

static void clearCencStruct(GstStructure*& structure)
{
    gst_structure_set_name(structure, gst_structure_get_string(structure, "original-media-type"));
    gst_structure_remove_field(structure, "protection-system");
    gst_structure_remove_field(structure, "original-media-type");
}

static GstCaps* gst_ocdmdecrypt_transform_caps(GstBaseTransform* trans, GstPadDirection direction,
    GstCaps* caps, GstCaps* filter)
{
    GstOcdmdecrypt* ocdmdecrypt = GST_OCDMDECRYPT(trans);
    GstCaps* othercaps;

    GST_DEBUG_OBJECT(ocdmdecrypt, "transform_caps");

    if (direction == GST_PAD_SRC) {
        // TODO:
        // Fired on reconfigure events.
        othercaps = gst_caps_copy(caps);
    } else {
        GST_INFO("Transforming caps going downstream");
        othercaps = gst_caps_new_empty();
        unsigned size = gst_caps_get_size(caps);
        for (unsigned i = 0; i < size; ++i) {
            GstStructure* incomingStructure = gst_caps_get_structure(caps, i);
            GstStructure* copyIncoming = gst_structure_copy(incomingStructure);

            // Removes all fields related to encryption, so the downstream caps intersection succeeds.
            clearCencStruct(copyIncoming);
            gst_caps_append_structure(othercaps, copyIncoming);
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

// TODO ?:
static gboolean gst_ocdmdecrypt_accept_caps(GstBaseTransform* trans, GstPadDirection direction,
    GstCaps* caps)
{
    GstOcdmdecrypt* ocdmdecrypt = GST_OCDMDECRYPT(trans);
    return TRUE;
}

static gboolean gst_ocdmdecrypt_sink_event(GstBaseTransform* trans, GstEvent* event)
{
    GstOcdmdecrypt* ocdmdecrypt = GST_OCDMDECRYPT(trans);
    GST_DEBUG_OBJECT(ocdmdecrypt, "sink_event");

    WPEFramework::Challenger challenger;

    switch (GST_EVENT_TYPE(event)) {
    case GST_EVENT_PROTECTION: {

        const char* systemId = nullptr;
        GstBuffer* dataBuffer = nullptr;
        gst_event_parse_protection(event, &systemId, &dataBuffer, nullptr);

        TRACE_L1("Got protection keysystem %s", systemId);

        if (ocdmdecrypt->ocdmSystem == nullptr) {
            TRACE_L1("Created ocdmsystem for widevine");
            ocdmdecrypt->ocdmSystem = opencdm_create_system("com.widevine.alpha");
            ASSERT(ocdmdecrypt->ocdmSystem != nullptr);

            if (ocdmdecrypt->ocdmSession == nullptr) {
                
                GstMapInfo map;
                gst_buffer_map(dataBuffer, &map, GST_MAP_READ);

                opencdm_construct_session(ocdmdecrypt->ocdmSystem,
                    LicenseType::Temporary,
                    "keyids",
                    map.data,
                    static_cast<uint16_t>(map.size),
                    nullptr,
                    0,
                    &challenger.OcdmCallbacks(),
                    &challenger,
                    &ocdmdecrypt->ocdmSession);
            }
        }

        TRACE_L1("unrefing event");
        gst_event_unref(event);
        return TRUE;
    }
    default: {
        return GST_BASE_TRANSFORM_CLASS(gst_ocdmdecrypt_parent_class)->sink_event(trans, event);
    }
    }
}

static GstFlowReturn gst_ocdmdecrypt_transform_ip(GstBaseTransform* trans, GstBuffer* buf)
{
    GstOcdmdecrypt* ocdmdecrypt = GST_OCDMDECRYPT(trans);

    GST_DEBUG_OBJECT(ocdmdecrypt, "transform_ip");

    return GST_FLOW_OK;
}

void gst_ocdmdecrypt_finalize(GObject* object)
{
    GstOcdmdecrypt* ocdmdecrypt = GST_OCDMDECRYPT(object);
    GST_DEBUG_OBJECT(ocdmdecrypt, "finalize");
    G_OBJECT_CLASS(gst_ocdmdecrypt_parent_class)->finalize(object);
}
