# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Simple RAG implementation for AWS resource data using ChromaDB."""

import json
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional


try:
    import chromadb
    from sentence_transformers import CrossEncoder, SentenceTransformer

    DEPENDENCIES_AVAILABLE = True
except ImportError:
    DEPENDENCIES_AVAILABLE = False
    # Type stubs for when dependencies are not available
    chromadb = None  # type: ignore
    CrossEncoder = None  # type: ignore
    SentenceTransformer = None  # type: ignore

from loguru import logger


class SimpleRAG:
    """Simple RAG system for AWS resource scan data."""

    # Class-level constants for resource type mappings
    IDENTIFIER_KEYS = [
        'BucketName',
        'InstanceId',
        'RoleName',
        'FunctionName',
        'DBInstanceIdentifier',
        'Name',
    ]

    RESOURCE_CONTEXTS = {
        'S3': 'This is a storage bucket resource.',
        'EC2': 'This is a compute resource.',
        'RDS': 'This is a database resource.',
        'IAM': 'This is a security/identity resource.',
        'Lambda': 'This is a serverless compute function.',
    }

    INSIGHT_CATEGORIES = {
        'security_sensitive': 'security-sensitive resources requiring access control review',
        'public_facing': 'public-facing resources that need security configuration verification',
        'high_cost_potential': 'high-cost resources for optimization consideration',
        'compliance_important': 'compliance-critical resources needing IaC management',
        'networking_critical': 'core networking infrastructure components',
    }

    def __init__(self, base_path: Optional[str] = None):
        """Initialize the RAG system."""
        if not DEPENDENCIES_AVAILABLE:
            raise ImportError(
                'RAG dependencies not available. '
                'Please install: pip install chromadb sentence-transformers'
            )

        self._setup_paths(base_path)
        self._initialize_chroma()
        self._initialize_embedding_model()
        self.metadata = self._load_metadata()

    def _setup_paths(self, base_path: Optional[str]) -> None:
        """Setup file paths for the RAG system."""
        self.base_path = Path(base_path) if base_path else Path.home() / '.cfn-mcp-rag'
        self.base_path.mkdir(parents=True, exist_ok=True)
        self.chroma_path = self.base_path / 'chroma_db'
        self.metadata_file = self.base_path / 'metadata.json'

    def _initialize_chroma(self) -> None:
        """Initialize ChromaDB client and collection."""
        if chromadb is None:
            raise ImportError('chromadb module is required but not available')
        self.chroma_client = chromadb.PersistentClient(path=str(self.chroma_path))
        self.collection = self.chroma_client.get_or_create_collection(
            name='aws-resources', metadata={'description': 'AWS CloudFormation resource scan data'}
        )

    def _initialize_embedding_model(self) -> None:
        """Initialize the sentence transformer model and cross-encoder."""
        if SentenceTransformer is None:
            raise ImportError('SentenceTransformer module is required but not available')

        try:
            # Bi-encoder for fast retrieval
            self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')

            # Cross-encoder for precise re-ranking (lazy loading)
            self._cross_encoder = None

        except Exception as e:
            logger.error(f'Failed to load embedding model: {e}')
            raise

    def _get_cross_encoder(self):
        """Lazy load the cross-encoder model for re-ranking."""
        if CrossEncoder is None:
            logger.warning(
                'CrossEncoder not available. Ensure sentence_transformers is installed.'
            )
            return None

        if self._cross_encoder is None:
            try:
                # Using a fast, lightweight cross-encoder model
                self._cross_encoder = CrossEncoder('cross-encoder/ms-marco-MiniLM-L6-v2')
                logger.info('Cross-encoder model loaded successfully')
            except Exception as e:
                logger.warning(
                    f'Failed to load cross-encoder: {e}. Falling back to bi-encoder only.'
                )
                self._cross_encoder = None
        return self._cross_encoder

    def _load_metadata(self) -> Dict:
        """Load metadata from file or create new."""
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f'Failed to load metadata: {e}')

        return {'stored_scans': {}, 'last_updated': None, 'total_documents': 0}

    def _save_metadata(self) -> None:
        """Save metadata to file."""
        try:
            with open(self.metadata_file, 'w') as f:
                json.dump(self.metadata, f, indent=2, default=str)
        except Exception as e:
            logger.error(f'Failed to save metadata: {e}')

    def _get_readable_identifier(self, identifier: Any) -> str:
        """Extract a human-readable ID from a resource identifier."""
        if isinstance(identifier, dict):
            for key in self.IDENTIFIER_KEYS:
                if key in identifier:
                    return identifier[key]
            return str(list(identifier.values())[0]) if identifier else 'Unknown'
        return str(identifier) if identifier else 'Unknown'

    def _get_resource_context(self, resource_type: str) -> str:
        """Get additional context based on resource type."""
        for service_prefix, context in self.RESOURCE_CONTEXTS.items():
            if service_prefix in resource_type:
                return context
        return ''

    def _generate_keywords(
        self, resource_type: str, readable_id: str, region: str, management_status: str
    ) -> List[str]:
        """Generate keywords for better embedding."""
        keywords = [resource_type, readable_id, region, management_status]

        keyword_mapping = {
            'S3': ['storage'],
            'EC2': ['compute'],
            'RDS': ['database'],
            'IAM': ['security'],
            'Lambda': ['serverless'],
        }

        for service, service_keywords in keyword_mapping.items():
            if service in resource_type:
                keywords.extend(service_keywords)
                break

        return keywords

    def _create_resource_document(self, resource: Dict, region: str, scan_id: str) -> Dict:
        """Create a document for a single resource with optimized text for embedding."""
        resource_type = resource.get('ResourceType', 'Unknown')
        identifier = resource.get('ResourceIdentifier', {})
        managed = resource.get('ManagedByStack', False)

        readable_id = self._get_readable_identifier(identifier)
        management_status = 'managed' if managed else 'unmanaged'
        keywords = self._generate_keywords(resource_type, readable_id, region, management_status)

        text = (
            f'Resource: {resource_type} | Name: {readable_id} | '
            f'Region: {region} | Status: {management_status} | '
            f'Keywords: {", ".join(keywords)}'
        )

        return {
            'id': str(uuid.uuid4()),
            'text': text,
            'metadata': {
                'type': 'resource',
                'region': region,
                'resource_type': resource_type,
                'managed': managed,
                'scan_id': scan_id,
                'identifier': str(identifier),
                'readable_id': readable_id,
            },
        }

    def _create_summary_document(self, scan_data: Dict, region: str, scan_id: str) -> Dict:
        """Create a summary document for the entire scan."""
        summary = scan_data.get('summary', {})
        critical_analysis = scan_data.get('critical_analysis', {})

        total_count = summary.get('total_count', 0)
        managed_count = summary.get('managed_count', 0)
        unmanaged_count = summary.get('unmanaged_count', 0)

        text = (
            f'Resource scan summary for {region} region: {total_count} total resources found, '
            f'{managed_count} managed by CloudFormation, {unmanaged_count} unmanaged resources. '
        )

        insights = critical_analysis.get('insights_summary', [])
        if insights:
            text += 'Key insights: ' + '; '.join(insights)

        return {
            'id': str(uuid.uuid4()),
            'text': text,
            'metadata': {
                'type': 'summary',
                'region': region,
                'scan_id': scan_id,
                'total_count': total_count,
                'managed_count': managed_count,
                'unmanaged_count': unmanaged_count,
            },
        }

    def _create_insights_documents(self, scan_data: Dict, region: str, scan_id: str) -> List[Dict]:
        """Create documents for critical insights."""
        documents = []
        critical_analysis = scan_data.get('critical_analysis', {})
        detailed_analysis = critical_analysis.get('detailed_analysis', {})

        for category, description in self.INSIGHT_CATEGORIES.items():
            resources = detailed_analysis.get(category, [])
            if not resources:
                continue

            resource_list = [f'{r["type"]} ({r["identifier"]})' for r in resources[:5]]
            text = f'Critical {description} in {region}: {", ".join(resource_list)}'
            if len(resources) > 5:
                text += f' and {len(resources) - 5} more'

            documents.append(
                {
                    'id': str(uuid.uuid4()),
                    'text': text,
                    'metadata': {
                        'type': 'insight',
                        'category': category,
                        'region': region,
                        'scan_id': scan_id,
                        'resource_count': len(resources),
                    },
                }
            )

        return documents

    def _create_all_documents(self, scan_data: Dict, region: str, scan_id: str) -> List[Dict]:
        """Create all documents from scan data."""
        documents = []

        # Add summary document
        documents.append(self._create_summary_document(scan_data, region, scan_id))

        # Add insights documents
        documents.extend(self._create_insights_documents(scan_data, region, scan_id))

        # Add resource documents
        all_resources = scan_data.get('resources', [])
        for resource in all_resources:
            documents.append(self._create_resource_document(resource, region, scan_id))

        # Add critical analysis resources
        documents.extend(self._create_critical_analysis_documents(scan_data, region, scan_id))

        return documents

    def _create_critical_analysis_documents(
        self, scan_data: Dict, region: str, scan_id: str
    ) -> List[Dict]:
        """Create documents for critical analysis resources."""
        documents = []
        critical_analysis = scan_data.get('critical_analysis', {})
        detailed_analysis = critical_analysis.get('detailed_analysis', {})

        for category_resources in detailed_analysis.values():
            if not isinstance(category_resources, list):
                continue

            for resource in category_resources:
                resource_doc = {
                    'ResourceType': resource.get('type', 'Unknown'),
                    'ResourceIdentifier': {'Name': resource.get('identifier', 'Unknown')},
                    'ManagedByStack': False,
                }

                doc = self._create_resource_document(resource_doc, region, scan_id)
                doc['id'] = f'{doc["id"]}-critical'
                doc['text'] += ' This resource was identified as requiring critical attention.'
                documents.append(doc)

        return documents

    def _deduplicate_documents(self, documents: List[Dict]) -> List[Dict]:
        """Remove duplicate documents based on ID."""
        unique_documents = {}
        for doc in documents:
            unique_documents[doc['id']] = doc
        return list(unique_documents.values())

    def _batch_add_documents(self, documents: List[Dict]) -> None:
        """Add documents to ChromaDB in batches with deduplication."""
        if not documents:
            return

        # Prepare data for ChromaDB
        texts = [doc['text'] for doc in documents]
        embeddings = self.embedding_model.encode(texts).tolist()
        ids = [doc['id'] for doc in documents]
        metadatas = [doc['metadata'] for doc in documents]

        # Filter out existing documents
        try:
            existing_docs = self.collection.get(ids=ids)
            existing_ids = set(existing_docs['ids']) if existing_docs.get('ids') else set()
        except Exception:
            existing_ids = set()

        # Prepare new documents only
        new_data = [
            (emb, txt, meta, doc_id)
            for emb, txt, meta, doc_id in zip(embeddings, texts, metadatas, ids)
            if doc_id not in existing_ids
        ]

        if new_data:
            new_embeddings, new_texts, new_metadatas, new_ids = zip(*new_data)
            self.collection.add(
                embeddings=list(new_embeddings),
                documents=list(new_texts),
                metadatas=list(new_metadatas),
                ids=list(new_ids),
            )

    def store_scan_data(self, scan_data: Dict, region: str) -> Dict:
        """Store resource scan data in the vector database."""
        try:
            if isinstance(scan_data, str):
                scan_data = json.loads(scan_data)

            scan_metadata = scan_data.get('scan_metadata', {})
            scan_id = scan_metadata.get('scan_id', 'unknown')

            if scan_id in self.metadata.get('stored_scans', {}):
                logger.info(f'Scan {scan_id} already exists, updating with new data')

            # Create all documents
            documents = self._create_all_documents(scan_data, region, scan_id)
            documents = self._deduplicate_documents(documents)

            if documents:
                self._batch_add_documents(documents)
                self._update_metadata(
                    scan_id, region, len(documents), scan_metadata.get('end_time')
                )

                return {
                    'status': 'success',
                    'message': f'Stored {len(documents)} documents from {region} scan in RAG system',
                    'scan_id': scan_id,
                    'document_count': len(documents),
                }
            else:
                return {
                    'status': 'no_data',
                    'message': f'No documents created from scan data for region {region}',
                    'scan_id': scan_id,
                }

        except Exception as e:
            logger.error(f'Error storing scan data: {e}')
            return {'status': 'error', 'message': f'Failed to store scan data: {str(e)}'}

    def _update_metadata(
        self, scan_id: str, region: str, doc_count: int, end_time: Optional[str]
    ) -> None:
        """Update metadata with new scan information."""
        self.metadata['stored_scans'][scan_id] = {
            'region': region,
            'document_count': doc_count,
            'timestamp': end_time,
        }
        self.metadata['total_documents'] += doc_count
        self.metadata['last_updated'] = end_time
        self._save_metadata()

    def query(self, query: str, region: str = '', limit: int = 5) -> Dict:
        """Query the stored resource data using natural language with cross-encoder re-ranking."""
        try:
            # Step 1: Use bi-encoder for fast retrieval (get more candidates for re-ranking)
            initial_limit = min(limit * 3, 20)  # Get 3x more results for re-ranking, but cap at 20
            query_embedding = self.embedding_model.encode([query]).tolist()[0]

            # Only add where_clause if region is provided and not empty
            where_clause = {'region': region} if region and region.strip() else None

            if where_clause:
                results = self.collection.query(
                    query_embeddings=[query_embedding],
                    n_results=initial_limit,
                    where=where_clause,  # type: ignore
                )
            else:
                results = self.collection.query(
                    query_embeddings=[query_embedding], n_results=initial_limit
                )

            if (
                not results.get('documents')
                or not results['documents']
                or not results['documents'][0]
            ):
                return {
                    'status': 'success',
                    'query': query,
                    'region_filter': region,
                    'result_count': 0,
                    'results': [],
                    'reranked': False,
                }

            documents = (
                results['documents'][0]
                if results.get('documents') and results['documents']
                else []
            )
            distances = (
                results['distances'][0]
                if results.get('distances') and results['distances'] and results['distances'][0]
                else [1.0] * len(documents)
            )

            # Step 2: Apply cross-encoder re-ranking if available
            cross_encoder = self._get_cross_encoder()
            if cross_encoder is not None and documents and len(documents) > 1:
                try:
                    # Prepare query-document pairs for cross-encoder
                    query_doc_pairs = [(query, doc) for doc in documents]

                    # Get cross-encoder scores (higher is better)
                    cross_scores = cross_encoder.predict(query_doc_pairs)

                    # Sort by cross-encoder scores (descending)
                    scored_results = list(zip(documents, cross_scores))
                    scored_results.sort(key=lambda x: x[1], reverse=True)

                    # Take top results after re-ranking
                    final_results = scored_results[:limit]

                    formatted_results = [
                        {
                            'text': doc,
                            'similarity_score': float(score)
                            if score >= 0
                            else abs(float(score)),  # Convert negative scores to positive
                            'reranked': True,
                        }
                        for doc, score in final_results
                    ]

                except Exception as e:
                    logger.warning(
                        f'Cross-encoder re-ranking failed: {e}. Using bi-encoder results.'
                    )
                    # Fallback to bi-encoder results
                    formatted_results = self._format_biencoder_results(
                        documents[:limit], distances[:limit]
                    )
            else:
                # Use bi-encoder results only
                formatted_results = self._format_biencoder_results(
                    documents[:limit], distances[:limit]
                )

            return {
                'status': 'success',
                'query': query,
                'region_filter': region,
                'result_count': len(formatted_results),
                'results': formatted_results,
                'reranked': cross_encoder is not None and documents and len(documents) > 1,
            }

        except Exception as e:
            logger.error(f'Error querying RAG system: {e}')
            return {
                'status': 'error',
                'message': f'Failed to query RAG system: {str(e)}',
                'results': [],
                'reranked': False,
            }

    def _format_biencoder_results(
        self, documents: List[str], distances: List[float]
    ) -> List[Dict]:
        """Format bi-encoder results for consistency."""
        return [
            {
                'text': doc,
                'similarity_score': 1 - distance,  # Convert distance to similarity
                'reranked': False,
            }
            for doc, distance in zip(documents, distances)
        ]

    def clear_cache(self, region: Optional[str] = None) -> Dict:
        """Clear RAG cache from all regions."""
        try:
            all_docs = self.collection.get()
            deleted_count = len(all_docs.get('ids', []))

            if deleted_count > 0:
                self.collection.delete(ids=all_docs['ids'])
        except Exception:
            # Fallback: recreate the collection
            self.chroma_client.delete_collection('aws-resources')
            self.collection = self.chroma_client.get_or_create_collection(
                name='aws-resources',
                metadata={'description': 'AWS CloudFormation resource scan data'},
            )
            deleted_count = self.metadata.get('total_documents', 0)

        # Reset metadata
        self.metadata = {'stored_scans': {}, 'last_updated': None, 'total_documents': 0}
        self._save_metadata()

        return {
            'status': 'success',
            'message': f'Cleared all RAG cache ({deleted_count} documents)',
            'deleted_count': deleted_count,
        }

    def get_stats(self) -> Dict:
        """Get RAG system statistics."""
        try:
            collection_count = self.collection.count()

            return {
                'status': 'success',
                'total_documents': collection_count,
                'stored_scans': len(self.metadata.get('stored_scans', {})),
                'last_updated': self.metadata.get('last_updated'),
                'storage_path': str(self.base_path),
                'scans_by_region': {
                    scan_info['region']: scan_id
                    for scan_id, scan_info in self.metadata.get('stored_scans', {}).items()
                    if scan_info and isinstance(scan_info, dict) and 'region' in scan_info
                },
            }

        except Exception as e:
            logger.error(f'Error getting RAG stats: {e}')
            return {'status': 'error', 'message': f'Failed to get RAG statistics: {str(e)}'}


# Global RAG instance
_rag_instance = None


def get_rag_instance() -> SimpleRAG:
    """Get or create the global RAG instance."""
    global _rag_instance
    if _rag_instance is None:
        _rag_instance = SimpleRAG()
    return _rag_instance
