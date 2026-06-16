/*
 * nvidia_triton.c
 *
 * Copyright (C) 2026 - ntop.org
 *
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the OpenDPI and PACE technology by ipoque GmbH
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_NVIDIA_TRITON

#include "ndpi_api.h"
#include "ndpi_private.h"

/* NVIDIA Triton Inference Server
   Default ports: 8000 (HTTP), 8001 (gRPC), 8002 (metrics)
   KServe inference protocol:
   - GET /v2 → {"server_id":"triton","version":"2.x","extensions":[...]}
   - GET /v2/health/live, /v2/health/ready
   - GET /v2/models, /v2/models/{name}
   - POST /v2/models/{name}/infer */

static int triton_has_primary_signature(const char *payload_str, u_int16_t payload_len)
{
  if(payload_len <= 10)
    return 0;

  return(ndpi_strnstr(payload_str, "\"server_id\"", payload_len) != NULL &&
         ndpi_strnstr(payload_str, "triton", payload_len) != NULL);
}

static int triton_has_secondary_signature(struct ndpi_packet_struct *packet,
                                          const char *payload_str,
                                          u_int16_t payload_len)
{
  if(packet->server_line.ptr != NULL && packet->server_line.len > 0 &&
     ndpi_strncasestr((const char *)packet->server_line.ptr, "triton", packet->server_line.len) != NULL)
    return 1;

  /* Server metadata compatible with KServe v2: {"name":"triton", "version":"...", "extensions":[...]} */
  if(payload_len > 20 &&
     ndpi_strnstr(payload_str, "\"name\":\"triton\"", payload_len) != NULL &&
     ndpi_strnstr(payload_str, "\"version\"", payload_len) != NULL &&
     ndpi_strnstr(payload_str, "\"extensions\"", payload_len) != NULL)
    return 1;

  return 0;
}

static void ndpi_search_nvidia_triton(struct ndpi_detection_module_struct *ndpi_struct,
                                        struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  const char *payload_str = (const char *)packet->payload;
  u_int16_t payload_len = packet->payload_packet_len;
  int weak_path_match = 0;
  int strong_signature_match = 0;

  NDPI_LOG_DBG(ndpi_struct, "search NVIDIA Triton\n");

  /* Helper: extract model name from a /v2/models/<name>/... path */
  #define EXTRACT_TRITON_MODEL_FROM_PATH(path, path_len) do { \
    const char *mp = ndpi_strnstr(path, "/v2/models/", path_len); \
    if(mp != NULL) { \
      const char *mn = mp + 11; \
      const char *me = ndpi_strnstr(mn, "/", path_len - (mn - path)); \
      if(me == NULL) me = mp + path_len - (mp - path); /* end of string if no trailing / */ \
      size_t mlen = me - mn; \
      if(mlen > 0 && mlen < sizeof(flow->protos.nvidia_triton.model_name)) { \
        memcpy(flow->protos.nvidia_triton.model_name, mn, mlen); \
        flow->protos.nvidia_triton.model_name[mlen] = '\0'; \
      } \
    } \
  } while(0)

  /* Case 1: Triton over HTTP */
  if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_HTTP ||
     flow->detected_protocol_stack[1] == NDPI_PROTOCOL_HTTP) {

    strong_signature_match = triton_has_primary_signature(payload_str, payload_len) ||
                             triton_has_secondary_signature(packet, payload_str, payload_len);

    /* Check URL path for Triton-specific /v2/ KServe endpoints */
    if(packet->http_url_name.ptr != NULL && packet->http_url_name.len > 0) {
      const char *url = (const char *)packet->http_url_name.ptr;
      u_int16_t url_len = packet->http_url_name.len;

      if(ndpi_strnstr(url, "/v2/health/", url_len) != NULL ||
         ndpi_strnstr(url, "/v2/models/", url_len) != NULL ||
         LINE_ENDS(packet->http_url_name, "/v2") ||
         ndpi_strnstr(url, "/infer", url_len) != NULL) {
        weak_path_match = 1;

        /* Save the specific endpoint */
        if(ndpi_strnstr(url, "/v2/health/live", url_len) != NULL)
          snprintf(flow->protos.nvidia_triton.endpoint,
                   sizeof(flow->protos.nvidia_triton.endpoint), "%s", "/v2/health/live");
        else if(ndpi_strnstr(url, "/v2/health/ready", url_len) != NULL)
          snprintf(flow->protos.nvidia_triton.endpoint,
                   sizeof(flow->protos.nvidia_triton.endpoint), "%s", "/v2/health/ready");
        else if(ndpi_strnstr(url, "/v2/models/", url_len) != NULL) {
          /* Capture as much of the path as fits */
          size_t ep_len = url_len < sizeof(flow->protos.nvidia_triton.endpoint) - 1
                          ? url_len : sizeof(flow->protos.nvidia_triton.endpoint) - 1;
          memcpy(flow->protos.nvidia_triton.endpoint, url, ep_len);
          flow->protos.nvidia_triton.endpoint[ep_len] = '\0';
          EXTRACT_TRITON_MODEL_FROM_PATH(url, url_len);
        } else if(LINE_ENDS(packet->http_url_name, "/v2"))
          snprintf(flow->protos.nvidia_triton.endpoint,
                   sizeof(flow->protos.nvidia_triton.endpoint), "%s", "/v2");
        else if(ndpi_strnstr(url, "/infer", url_len) != NULL) {
          size_t ep_len = url_len < sizeof(flow->protos.nvidia_triton.endpoint) - 1
                          ? url_len : sizeof(flow->protos.nvidia_triton.endpoint) - 1;
          memcpy(flow->protos.nvidia_triton.endpoint, url, ep_len);
          flow->protos.nvidia_triton.endpoint[ep_len] = '\0';
        }

      }
    }

    if(strong_signature_match) {
      NDPI_LOG_INFO(ndpi_struct, "found NVIDIA Triton (strong signature)\n");

      /* Extract server version if present: "version":"2.x" */
      if(payload_len > 11) {
        const char *v = ndpi_strnstr(payload_str, "\"version\":\"", payload_len);
        if(v != NULL) {
          const char *vv = v + 11;
          const char *ve = ndpi_strnstr(vv, "\"", payload_len - (vv - payload_str));
          if(ve != NULL) {
            size_t vlen = ve - vv;
            if(vlen < sizeof(flow->protos.nvidia_triton.server_version)) {
              memcpy(flow->protos.nvidia_triton.server_version, vv, vlen);
              flow->protos.nvidia_triton.server_version[vlen] = '\0';
            }
          }
        }
      }

      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_NVIDIA_TRITON,
                                 NDPI_PROTOCOL_HTTP, NDPI_CONFIDENCE_DPI);
      return;
    }

    /* Keep the dissector active if a KServe v2 path is seen, waiting for strong confirmation. */
    if(weak_path_match)
      return;

    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  /* Case 2: Triton over raw TCP */
  if(packet->tcp != NULL && payload_len > 10) {
    strong_signature_match = triton_has_primary_signature(payload_str, payload_len) ||
                             triton_has_secondary_signature(packet, payload_str, payload_len);

    if(strong_signature_match) {
      NDPI_LOG_INFO(ndpi_struct, "found NVIDIA Triton (raw TCP strong signature)\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_NVIDIA_TRITON,
                                 NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
      return;
    }
  }

  NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
  #undef EXTRACT_TRITON_MODEL_FROM_PATH
}

void init_nvidia_triton_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("NVIDIA_Triton", ndpi_struct,
                     ndpi_search_nvidia_triton,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                     1, NDPI_PROTOCOL_NVIDIA_TRITON);
}