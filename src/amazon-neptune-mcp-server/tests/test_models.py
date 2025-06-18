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
"""Tests for the data models."""

from awslabs.amazon_neptune_mcp_server.models import (
    GraphSchema,
    Node,
    Property,
    Relationship,
    RelationshipPattern,
)


class TestModels:
    """Test class for the data model classes."""

    def test_property_model(self):
        """Test the Property model creation and serialization.

        This test verifies that:
        1. A Property can be created with name and type attributes
        2. The attributes are correctly accessible
        3. The model serializes correctly to a dictionary
        """
        # Create a property
        prop = Property(name='age', type=['INTEGER'])

        # Verify attributes
        assert prop.name == 'age'
        assert prop.type == ['INTEGER']

        # Test serialization
        prop_dict = prop.model_dump()
        assert prop_dict == {'name': 'age', 'type': ['INTEGER']}

    def test_node_model(self):
        """Test the Node model creation and serialization with properties.

        This test verifies that:
        1. A Node can be created with labels and properties
        2. The attributes are correctly accessible
        3. The model serializes correctly to a dictionary
        """
        # Create properties
        name_prop = Property(name='name', type=['STRING'])
        age_prop = Property(name='age', type=['INTEGER'])

        # Create a node with properties
        node = Node(labels='Person', properties=[name_prop, age_prop])

        # Verify attributes
        assert node.labels == 'Person'
        assert len(node.properties) == 2
        assert node.properties[0].name == 'name'
        assert node.properties[1].name == 'age'

        # Test serialization
        node_dict = node.model_dump()
        assert node_dict['labels'] == 'Person'
        assert len(node_dict['properties']) == 2

    def test_node_model_without_properties(self):
        """Test the Node model creation and serialization without properties.

        This test verifies that:
        1. A Node can be created with only labels
        2. The properties attribute defaults to an empty list
        3. The model serializes correctly to a dictionary
        """
        # Create a node without properties
        node = Node(labels='EmptyNode')

        # Verify attributes
        assert node.labels == 'EmptyNode'
        assert node.properties == []

        # Test serialization
        node_dict = node.model_dump()
        assert node_dict['labels'] == 'EmptyNode'
        assert node_dict['properties'] == []

    def test_relationship_model(self):
        """Test the Relationship model creation and serialization with properties.

        This test verifies that:
        1. A Relationship can be created with type and properties
        2. The attributes are correctly accessible
        3. The model serializes correctly to a dictionary
        """
        # Create properties
        since_prop = Property(name='since', type=['DATE'])

        # Create a relationship with properties
        rel = Relationship(type='KNOWS', properties=[since_prop])

        # Verify attributes
        assert rel.type == 'KNOWS'
        assert len(rel.properties) == 1
        assert rel.properties[0].name == 'since'

        # Test serialization
        rel_dict = rel.model_dump()
        assert rel_dict['type'] == 'KNOWS'
        assert len(rel_dict['properties']) == 1

    def test_relationship_model_without_properties(self):
        """Test the Relationship model creation and serialization without properties.

        This test verifies that:
        1. A Relationship can be created with only type
        2. The properties attribute defaults to an empty list
        3. The model serializes correctly to a dictionary
        """
        # Create a relationship without properties
        rel = Relationship(type='FOLLOWS')

        # Verify attributes
        assert rel.type == 'FOLLOWS'
        assert rel.properties == []

        # Test serialization
        rel_dict = rel.model_dump()
        assert rel_dict['type'] == 'FOLLOWS'
        assert rel_dict['properties'] == []

    def test_relationship_pattern_model(self):
        """Test the RelationshipPattern model creation and serialization.

        This test verifies that:
        1. A RelationshipPattern can be created with left_node, right_node, and relation
        2. The attributes are correctly accessible
        3. The model serializes correctly to a dictionary
        """
        # Create a relationship pattern
        pattern = RelationshipPattern(left_node='Person', right_node='Person', relation='KNOWS')

        # Verify attributes
        assert pattern.left_node == 'Person'
        assert pattern.right_node == 'Person'
        assert pattern.relation == 'KNOWS'

        # Test serialization
        pattern_dict = pattern.model_dump()
        assert pattern_dict['left_node'] == 'Person'
        assert pattern_dict['right_node'] == 'Person'
        assert pattern_dict['relation'] == 'KNOWS'

    def test_graph_schema_model(self):
        """Test the GraphSchema model creation and serialization.

        This test verifies that:
        1. A GraphSchema can be created with nodes, relationships, and relationship_patterns
        2. The attributes are correctly accessible
        3. The model serializes correctly to a dictionary
        """
        # Create nodes
        person_node = Node(
            labels='Person',
            properties=[
                Property(name='name', type=['STRING']),
                Property(name='age', type=['INTEGER']),
            ],
        )

        city_node = Node(
            labels='City',
            properties=[
                Property(name='name', type=['STRING']),
                Property(name='population', type=['INTEGER']),
            ],
        )

        # Create relationships
        knows_rel = Relationship(type='KNOWS', properties=[Property(name='since', type=['DATE'])])

        lives_in_rel = Relationship(type='LIVES_IN')

        # Create relationship patterns
        person_knows_person = RelationshipPattern(
            left_node='Person', right_node='Person', relation='KNOWS'
        )

        person_lives_in_city = RelationshipPattern(
            left_node='Person', right_node='City', relation='LIVES_IN'
        )

        # Create graph schema
        schema = GraphSchema(
            nodes=[person_node, city_node],
            relationships=[knows_rel, lives_in_rel],
            relationship_patterns=[person_knows_person, person_lives_in_city],
        )

        # Verify attributes
        assert len(schema.nodes) == 2
        assert len(schema.relationships) == 2
        assert len(schema.relationship_patterns) == 2

        # Test serialization
        schema_dict = schema.model_dump()
        assert len(schema_dict['nodes']) == 2
        assert len(schema_dict['relationships']) == 2
        assert len(schema_dict['relationship_patterns']) == 2
