/*
 * Registry editor
 *
 * Copyright 2009 Mike McCormack
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <QApplication>
#include <QTreeView>
#include <QListView>
#include <QAbstractItemModel>
#include <qstring.h>
#include <assert.h>
#include <stdio.h>
#include "registryeditor.h"

RegistryEditor::RegistryEditor( struct hive* h ) :
	hive( h )
{
	QString kn( "\\" );

	rootItem = new RegistryItem( hive, NULL, kn );
	keyModel = new RegistryItemModel( rootItem, hive );
	keylist = new RegistryTreeView;

	keylist->setModel( keyModel );
	keylist->setWindowTitle(QObject::tr("Registry editor"));

	valueModel = new RegistryValueModel;

	valuelist = new QListView;
	valuelist->setModel( valueModel );

	layout = new QHBoxLayout;

	bool r = connect( keylist, SIGNAL(onSelectionChanged(const QModelIndex&, const QModelIndex&)),
			 this, SLOT(key_changed(const QModelIndex&, const QModelIndex&)));
	if (!r)
		throw;

	layout->addWidget( keylist );
	layout->addWidget( valuelist );

	setLayout( layout );
}

void RegistryEditor::key_changed( const QModelIndex &current, const QModelIndex & /*previous*/ )
{
	fprintf(stderr,"key_changed %p\n", &current);
	RegistryItem *item = static_cast<RegistryItem*>( current.internalPointer() );
	QString path = item->getPath();
	char *utf8_path = path.toUtf8().data();
	fprintf(stderr, "path = %s\n", utf8_path);
}
