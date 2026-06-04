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

static void ndpi_search_nvidia_triton(struct ndpi_detection_module_struct *ndpi_struct,
                                        struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search NVIDIA Triton\n");

  /* Case 1: Triton over HTTP */
  if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_HTTP ||
     flow->detected_protocol_stack[1] == NDPI_PROTOCOL_HTTP) {

    /* Check for "server_id":"triton" in response body - most distinctive */
    if(packet->payload_packet_len > 10 &&
       ndpi_strnstr((const char *)packet->payload, "\"server_id\"",
                    packet->payload_packet_len) != NULL &&
       ndpi_strnstr((const char *)packet->payload, "triton",
                    packet->payload_packet_len) != NULL) {
      NDPI_LOG_INFO(ndpi_struct, "found NVIDIA Triton (server_id in body)\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_NVIDIA_TRITON,
                                 NDPI_PROTOCOL_HTTP, NDPI_CONFIDENCE_DPI);
      return;
    }

    /* Check URL path for Triton-specific /v2/ KServe endpoints */
    if(packet->http_url_name.ptr != NULL && packet->http_url_name.len > 0) {
      if(ndpi_strnstr((const char *)packet->http_url_name.ptr, "/v2/health/",
                     packet->http_url_name.len) != NULL ||
         ndpi_strnstr((const char *)packet->http_url_name.ptr, "/v2/models/",
                     packet->http_url_name.len) != NULL ||
         LINE_ENDS(packet->http_url_name, "/v2") ||
         ndpi_strnstr((const char *)packet->http_url_name.ptr, "/infer",
                     packet->http_url_name.len) != NULL) {
        NDPI_LOG_INFO(ndpi_struct, "found NVIDIA Triton (/v2/ URL path)\n");
        ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_NVIDIA_TRITON,
                                   NDPI_PROTOCOL_HTTP, NDPI_CONFIDENCE_DPI);
        return;
      }
    }

    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  /* Case 2: Triton over raw TCP */
  if(packet->tcp != NULL && packet->payload_packet_len > 10) {
    /* Check for "server_id":"triton" in response */
    if(ndpi_strnstr((const char *)packet->payload, "\"server_id\"",
                    packet->payload_packet_len) != NULL &&
       ndpi_strnstr((const char *)packet->payload, "triton",
                    packet->payload_packet_len) != NULL) {
      NDPI_LOG_INFO(ndpi_struct, "found NVIDIA Triton (raw TCP)\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_NVIDIA_TRITON,
                                 NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
      return;
    }

    /* Check for HTTP request with /v2/ path */
    if(packet->payload_packet_len > 6 &&
       (memcmp(packet->payload, "GET ", 4) == 0 || memcmp(packet->payload, "POST ", 5) == 0) &&
       ndpi_strnstr((const char *)packet->payload, "/v2/",
                    packet->payload_packet_len) != NULL) {
      NDPI_LOG_INFO(ndpi_struct, "found NVIDIA Triton (raw TCP request)\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_NVIDIA_TRITON,
                                 NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
      return;
    }
  }

  NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
}

void init_nvidia_triton_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("NVIDIA_Triton", ndpi_struct,
                     ndpi_search_nvidia_triton,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                     1, NDPI_PROTOCOL_NVIDIA_TRITON);
}