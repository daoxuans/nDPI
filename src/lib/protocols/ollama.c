/*
 * ollama.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_OLLAMA

#include "ndpi_api.h"
#include "ndpi_private.h"

/* Ollama - local LLM inference server
   Default port: 11434
   HTTP REST API with distinctive endpoints:
   - GET / → "Ollama is running" (plain text, unique fingerprint)
   - GET /api/version → {"version":"0.x.x"}
   - POST /api/chat, POST /api/generate */

static void ndpi_search_ollama(struct ndpi_detection_module_struct *ndpi_struct,
                                struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search Ollama\n");

  /* Case 1: Ollama over HTTP */
  if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_HTTP ||
     flow->detected_protocol_stack[1] == NDPI_PROTOCOL_HTTP) {

    /* Check response body for "Ollama is running" - most distinctive signature */
    if(packet->payload_packet_len >= 17 &&
       ndpi_strnstr((const char *)packet->payload, "Ollama is running",
                    packet->payload_packet_len) != NULL) {
      NDPI_LOG_INFO(ndpi_struct, "found Ollama (response body)\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_OLLAMA,
                                 NDPI_PROTOCOL_HTTP, NDPI_CONFIDENCE_DPI);
      return;
    }

    /* Check URL path for Ollama-specific /api/ endpoints */
    if(packet->http_url_name.ptr != NULL && packet->http_url_name.len > 0) {
      if(ndpi_strnstr((const char *)packet->http_url_name.ptr, "/api/chat",
                     packet->http_url_name.len) != NULL ||
         ndpi_strnstr((const char *)packet->http_url_name.ptr, "/api/generate",
                     packet->http_url_name.len) != NULL ||
         ndpi_strnstr((const char *)packet->http_url_name.ptr, "/api/tags",
                     packet->http_url_name.len) != NULL ||
         ndpi_strnstr((const char *)packet->http_url_name.ptr, "/api/version",
                     packet->http_url_name.len) != NULL ||
         ndpi_strnstr((const char *)packet->http_url_name.ptr, "/api/show",
                     packet->http_url_name.len) != NULL ||
         ndpi_strnstr((const char *)packet->http_url_name.ptr, "/api/push",
                     packet->http_url_name.len) != NULL ||
         ndpi_strnstr((const char *)packet->http_url_name.ptr, "/api/create",
                     packet->http_url_name.len) != NULL ||
         ndpi_strnstr((const char *)packet->http_url_name.ptr, "/api/delete",
                     packet->http_url_name.len) != NULL ||
         ndpi_strnstr((const char *)packet->http_url_name.ptr, "/api/copy",
                     packet->http_url_name.len) != NULL ||
         ndpi_strnstr((const char *)packet->http_url_name.ptr, "/api/ps",
                     packet->http_url_name.len) != NULL) {
        NDPI_LOG_INFO(ndpi_struct, "found Ollama (/api/ URL path)\n");
        ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_OLLAMA,
                                   NDPI_PROTOCOL_HTTP, NDPI_CONFIDENCE_DPI);
        return;
      }
    }

    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  /* Case 2: Ollama over raw TCP (port 11434, cleartext HTTP without prior detection) */
  if(packet->tcp != NULL && packet->payload_packet_len > 17) {
    /* Check for "Ollama is running" in response */
    if(ndpi_strnstr((const char *)packet->payload, "Ollama is running",
                    packet->payload_packet_len) != NULL) {
      NDPI_LOG_INFO(ndpi_struct, "found Ollama (raw TCP)\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_OLLAMA,
                                 NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
      return;
    }

    /* Check for HTTP request with /api/ path to Ollama */
    if(packet->payload_packet_len > 6 &&
       (memcmp(packet->payload, "GET ", 4) == 0 || memcmp(packet->payload, "POST ", 5) == 0) &&
       ndpi_strnstr((const char *)packet->payload, "/api/",
                    packet->payload_packet_len) != NULL) {
      NDPI_LOG_INFO(ndpi_struct, "found Ollama (raw TCP request)\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_OLLAMA,
                                 NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
      return;
    }
  }

  NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
}

void init_ollama_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("Ollama", ndpi_struct,
                     ndpi_search_ollama,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                     1, NDPI_PROTOCOL_OLLAMA);
}